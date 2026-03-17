import CommonCrypto
import CryptoKit
import ExpoModulesCore
import LocalAuthentication

// MARK: - Error handling

private struct ModuleError: Error {
  let code: String
  let message: String
}

private enum ErrorCode {
  static let keyNotFound = "KEY_NOT_FOUND"
  static let keyAlreadyExists = "KEY_ALREADY_EXISTS"
  static let biometricCancelled = "BIOMETRIC_CANCELLED"
  static let biometricLockout = "BIOMETRIC_LOCKOUT"
  static let biometricNotEnrolled = "BIOMETRIC_NOT_ENROLLED"
  static let keyInvalidated = "KEY_INVALIDATED"
  static let hardwareUnavailable = "HARDWARE_UNAVAILABLE"
  static let unknown = "UNKNOWN"
}

// MARK: - Encoding

private func applicationTag(_ keyId: String) -> Data {
  "expo.hardware.key.\(keyId)".data(using: .utf8)!
}

private func sha256(_ data: Data) -> Data {
  var digest = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
  data.withUnsafeBytes { _ = CC_SHA256($0.baseAddress, CC_LONG(data.count), &digest) }
  return Data(digest)
}

/// Convert uncompressed 65-byte P-256 key (0x04 + X + Y) to 33-byte compressed (0x02/0x03 + X).
private func compressPublicKey(_ uncompressed: Data) -> Data? {
  var xy = uncompressed
  if xy.count == 65 && xy[0] == 0x04 { xy = xy.dropFirst() }
  guard xy.count == 64 else { return nil }
  let prefix: UInt8 = (xy.last ?? 0) % 2 == 0 ? 0x02 : 0x03
  return Data([prefix]) + xy.prefix(32)
}

// MARK: - DER signature parsing

private func parseDERSequenceOffset(_ bytes: [UInt8]) -> Int? {
  guard bytes.count > 2, bytes[0] == 0x30 else { return nil }
  var i = 1
  if bytes[i] & 0x80 != 0 {
    i += Int(bytes[i] & 0x7f) + 1
  } else {
    i += 1
  }
  return i
}

private func parseDERInteger(_ bytes: [UInt8], at i: inout Int) -> [UInt8]? {
  guard i < bytes.count, bytes[i] == 0x02 else { return nil }
  i += 1
  guard i < bytes.count else { return nil }
  let len = Int(bytes[i])
  i += 1
  guard i + len <= bytes.count else { return nil }
  let value = Array(bytes[i..<i + len])
  i += len
  return value
}

private func padOrTrimTo32(_ value: [UInt8]) -> [UInt8] {
  var v = value
  while v.count > 32 && v.first == 0x00 { v.removeFirst() }
  while v.count < 32 { v.insert(0x00, at: 0) }
  return v
}

private func derToRawRS(_ der: Data) -> Data? {
  let b = [UInt8](der)
  guard var i = parseDERSequenceOffset(b) else { return nil }
  guard let r = parseDERInteger(b, at: &i) else { return nil }
  guard let s = parseDERInteger(b, at: &i) else { return nil }
  let rPad = padOrTrimTo32(r)
  let sPad = padOrTrimTo32(s)
  guard rPad.count == 32, sPad.count == 32 else { return nil }
  return Data(rPad + sPad)
}

// MARK: - Async promise helper

private func runAsync(_ promise: Promise, body: @escaping () throws -> Any?) {
  DispatchQueue.global(qos: .userInitiated).async {
    do {
      promise.resolve(try body())
    } catch let e as ModuleError {
      promise.reject(e.code, e.message)
    } catch {
      promise.reject(ErrorCode.unknown, error.localizedDescription)
    }
  }
}

// MARK: - Module

public class ExpoHardwareKeyModule: Module {

  public func definition() -> ModuleDefinition {
    Name("ExpoHardwareKey")

    // biometricPrompt param (_) is accepted for JS API parity but not used;
    // iOS controls the prompt text through the system biometric dialog.

    AsyncFunction("generateKey") {
      (
        keyId: String, requireBiometrics: Bool, invalidateOnNewBiometric: Bool, _: String,
        promise: Promise
      ) in
      runAsync(promise) {
        try self.ensureKeyDoesNotExist(keyId)
        let useSecureEnclave = SecureEnclave.isAvailable
        let accessControl = try self.buildAccessControl(
          requireBiometrics: requireBiometrics,
          invalidateOnNewBiometric: invalidateOnNewBiometric
        )
        let privateKey = try self.generateSecureKey(
          keyId: keyId, accessControl: accessControl, useSecureEnclave: useSecureEnclave
        )
        return try self.publicKeyResult(from: privateKey, secureEnclave: useSecureEnclave)
      }
    }

    AsyncFunction("sign") { (keyId: String, dataBase64: String, _: String, promise: Promise) in
      runAsync(promise) {
        let privateKey = try self.findRequiredKey(keyId)
        let data = try self.decodeBase64(dataBase64)
        let digest = sha256(data)
        let derSignature = try self.createSignature(with: privateKey, digest: digest, keyId: keyId)
        let rawSignature = try self.convertDERToRawRS(derSignature)
        return rawSignature.base64EncodedString()
      }
    }

    AsyncFunction("getPublicKey") { (keyId: String, promise: Promise) in
      runAsync(promise) {
        let privateKey = try self.findRequiredKey(keyId)
        return try self.publicKeyResult(from: privateKey, secureEnclave: SecureEnclave.isAvailable)
      }
    }

    AsyncFunction("keyExists") { (keyId: String, promise: Promise) in
      promise.resolve(self.findPrivateKey(keyId: keyId) != nil)
    }

    AsyncFunction("deleteKey") { (keyId: String, promise: Promise) in
      self.deleteFromKeychain(keyId)
      promise.resolve(nil)
    }

    AsyncFunction("isHardwareBackedAvailable") { (promise: Promise) in
      promise.resolve(SecureEnclave.isAvailable)
    }
  }

  // MARK: - Key lifecycle

  private func ensureKeyDoesNotExist(_ keyId: String) throws {
    if findPrivateKey(keyId: keyId) != nil {
      throw ModuleError(code: ErrorCode.keyAlreadyExists, message: "Key '\(keyId)' already exists")
    }
  }

  private func buildAccessControl(requireBiometrics: Bool, invalidateOnNewBiometric: Bool) throws
    -> SecAccessControl
  {
    var flags: SecAccessControlCreateFlags = .privateKeyUsage
    if requireBiometrics {
      let biometricPolicy: SecAccessControlCreateFlags =
        invalidateOnNewBiometric
        ? .biometryCurrentSet
        : .biometryAny
      flags = [flags, biometricPolicy]
    }
    guard
      let access = SecAccessControlCreateWithFlags(
        kCFAllocatorDefault, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, flags, nil
      )
    else {
      throw ModuleError(
        code: ErrorCode.hardwareUnavailable, message: "Failed to create access control")
    }
    return access
  }

  private func generateSecureKey(
    keyId: String, accessControl: SecAccessControl, useSecureEnclave: Bool
  ) throws -> SecKey {
    var attrs: [String: Any] = [
      kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
      kSecAttrKeySizeInBits as String: 256,
      kSecPrivateKeyAttrs as String: [
        kSecAttrIsPermanent as String: true,
        kSecAttrApplicationTag as String: applicationTag(keyId),
        kSecAttrAccessControl as String: accessControl,
      ],
    ]
    if useSecureEnclave {
      attrs[kSecAttrTokenID as String] = kSecAttrTokenIDSecureEnclave
    }

    var cfError: Unmanaged<CFError>?
    guard let key = SecKeyCreateRandomKey(attrs as CFDictionary, &cfError) else {
      let msg = cfError?.takeRetainedValue().localizedDescription ?? "unknown"
      throw ModuleError(
        code: ErrorCode.hardwareUnavailable, message: "Key generation failed: \(msg)")
    }
    return key
  }

  // MARK: - Key lookup

  private func findRequiredKey(_ keyId: String) throws -> SecKey {
    guard let key = findPrivateKey(keyId: keyId) else {
      throw ModuleError(code: ErrorCode.keyNotFound, message: "Key '\(keyId)' not found")
    }
    return key
  }

  private func findPrivateKey(keyId: String) -> SecKey? {
    let query: [String: Any] = [
      kSecClass as String: kSecClassKey,
      kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
      kSecAttrApplicationTag as String: applicationTag(keyId),
      kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
      kSecReturnRef as String: true,
    ]
    var item: CFTypeRef?
    guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess else { return nil }
    // swiftlint:disable:next force_cast — kSecReturnRef guarantees SecKey on success
    return (item as! SecKey)
  }

  private func deleteFromKeychain(_ keyId: String) {
    let query: [String: Any] = [
      kSecClass as String: kSecClassKey,
      kSecAttrApplicationTag as String: applicationTag(keyId),
      kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
    ]
    SecItemDelete(query as CFDictionary)
  }

  // MARK: - Signing

  private func decodeBase64(_ string: String) throws -> Data {
    guard let data = Data(base64Encoded: string) else {
      throw ModuleError(code: ErrorCode.unknown, message: "Invalid base64 data")
    }
    return data
  }

  private func createSignature(with privateKey: SecKey, digest: Data, keyId: String) throws -> Data
  {
    var cfError: Unmanaged<CFError>?
    guard
      let sig = SecKeyCreateSignature(
        privateKey, .ecdsaSignatureDigestX962SHA256, digest as CFData, &cfError
      ) as Data?
    else {
      throw mapSigningError(cfError?.takeRetainedValue(), keyId: keyId)
    }
    return sig
  }

  private func convertDERToRawRS(_ derSignature: Data) throws -> Data {
    guard let rawRS = derToRawRS(derSignature) else {
      throw ModuleError(code: ErrorCode.unknown, message: "Failed to parse DER signature")
    }
    return rawRS
  }

  // MARK: - Public key export

  private func exportCompressedPublicKey(from privateKey: SecKey) throws -> Data {
    guard let publicKey = SecKeyCopyPublicKey(privateKey),
      let pubData = SecKeyCopyExternalRepresentation(publicKey, nil) as Data?,
      let compressed = compressPublicKey(pubData)
    else {
      throw ModuleError(code: ErrorCode.unknown, message: "Failed to export public key")
    }
    return compressed
  }

  private func publicKeyResult(from privateKey: SecKey, secureEnclave: Bool) throws -> [String:
    String]
  {
    let compressed = try exportCompressedPublicKey(from: privateKey)
    return [
      "publicKeyBase64": compressed.base64EncodedString(),
      "securityLevel": secureEnclave ? "secure-enclave" : "software",
    ]
  }

  // MARK: - Error mapping

  private func mapSigningError(_ cfError: CFError?, keyId: String) -> ModuleError {
    guard let err = cfError else {
      return ModuleError(code: ErrorCode.unknown, message: "Unknown signing error")
    }
    let domain = CFErrorGetDomain(err) as String
    let code = CFErrorGetCode(err)

    if domain == NSOSStatusErrorDomain {
      switch Int32(exactly: code) ?? 0 {
      case errSecUserCanceled:
        return ModuleError(
          code: ErrorCode.biometricCancelled, message: "User cancelled authentication")
      case errSecAuthFailed:
        return ModuleError(
          code: ErrorCode.biometricLockout, message: "Biometric lockout — too many failed attempts")
      case errSecInteractionNotAllowed:
        return ModuleError(
          code: ErrorCode.keyInvalidated, message: "Key '\(keyId)' is no longer valid")
      default: break
      }
    }

    if domain == "com.apple.LocalAuthentication" {
      switch code {
      case Int(LAError.Code.userCancel.rawValue):
        return ModuleError(
          code: ErrorCode.biometricCancelled, message: "User cancelled authentication")
      case Int(LAError.Code.biometryLockout.rawValue):
        return ModuleError(code: ErrorCode.biometricLockout, message: "Biometric lockout")
      case Int(LAError.Code.biometryNotEnrolled.rawValue):
        return ModuleError(code: ErrorCode.biometricNotEnrolled, message: "No biometrics enrolled")
      default: break
      }
    }

    return ModuleError(code: ErrorCode.unknown, message: err.localizedDescription)
  }
}
