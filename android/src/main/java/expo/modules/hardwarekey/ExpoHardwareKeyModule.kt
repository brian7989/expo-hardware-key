package expo.modules.hardwarekey

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import android.security.keystore.UserNotAuthenticatedException
import android.util.Base64
import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition
import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.Signature
import java.security.interfaces.ECPublicKey

// region Error handling

private object ErrorCode {
  const val KEY_NOT_FOUND = "KEY_NOT_FOUND"
  const val KEY_ALREADY_EXISTS = "KEY_ALREADY_EXISTS"
  const val BIOMETRIC_CANCELLED = "BIOMETRIC_CANCELLED"
  const val BIOMETRIC_LOCKOUT = "BIOMETRIC_LOCKOUT"
  const val BIOMETRIC_NOT_ENROLLED = "BIOMETRIC_NOT_ENROLLED"
  const val KEY_INVALIDATED = "KEY_INVALIDATED"
  const val HARDWARE_UNAVAILABLE = "HARDWARE_UNAVAILABLE"
  const val NOT_SUPPORTED = "NOT_SUPPORTED"
  const val UNKNOWN = "UNKNOWN"
}

private class ModuleException(
  val errorCode: String,
  errorMessage: String,
) : Exception("$errorCode|$errorMessage")

// endregion

// region Encoding

/** Encode a BigInteger as exactly 32 bytes (big-endian, zero-padded). */
private fun BigInteger.toByteArray32(): ByteArray {
  val raw = this.toByteArray()
  return when {
    raw.size == 32 -> raw
    raw.size == 33 && raw[0] == 0x00.toByte() -> raw.drop(1).toByteArray()
    raw.size < 32 -> ByteArray(32 - raw.size) + raw
    else -> raw.takeLast(32).toByteArray()
  }
}

/** Convert an ECPublicKey to 33-byte compressed form: [0x02|0x03][X (32 bytes)]. */
private fun compressECPublicKey(ecPub: ECPublicKey): ByteArray {
  val x = ecPub.w.affineX.toByteArray32()
  val y = ecPub.w.affineY.toByteArray32()
  val prefix: Byte = if (y.last().toInt() and 1 == 0) 0x02 else 0x03
  return byteArrayOf(prefix) + x
}

// endregion

// region DER signature parsing

/** Strip leading zero padding and left-pad to exactly 32 bytes. */
private fun padTo32(b: ByteArray): ByteArray {
  var v = b
  while (v.size > 32 && v[0] == 0x00.toByte()) v = v.drop(1).toByteArray()
  return if (v.size < 32) ByteArray(32 - v.size) + v else v
}

/**
 * Convert a DER-encoded ECDSA signature to 64-byte raw r||s.
 * Returns null if the DER data is malformed.
 */
private fun derToRawRS(der: ByteArray): ByteArray? {
  if (der.size < 8 || der[0] != 0x30.toByte()) return null
  var i = 1

  // skip sequence length
  if (der[i].toInt() and 0x80 != 0) {
    i += (der[i].toInt() and 0x7f) + 1
  } else {
    i++
  }

  // parse r
  if (i >= der.size || der[i] != 0x02.toByte()) return null
  i++
  if (i >= der.size) return null
  val rLen = der[i].toInt() and 0xff; i++
  if (i + rLen > der.size) return null
  val r = der.sliceArray(i until i + rLen); i += rLen

  // parse s
  if (i >= der.size || der[i] != 0x02.toByte()) return null
  i++
  if (i >= der.size) return null
  val sLen = der[i].toInt() and 0xff; i++
  if (i + sLen > der.size) return null
  val s = der.sliceArray(i until i + sLen)

  val rPad = padTo32(r)
  val sPad = padTo32(s)
  if (rPad.size != 32 || sPad.size != 32) return null
  return rPad + sPad
}

// endregion

class ExpoHardwareKeyModule : Module() {

  private val keyStore: KeyStore by lazy {
    KeyStore.getInstance("AndroidKeyStore").also { it.load(null) }
  }

  override fun definition() = ModuleDefinition {
    Name("ExpoHardwareKey")

    // biometricPrompt is accepted for JS API parity but not used on Android;
    // biometric UI is managed by the system when the key requires authentication.

    AsyncFunction("generateKey") { keyId: String, requireBiometrics: Boolean,
                                   invalidateOnNewBiometric: Boolean, _: String ->
      ensureKeyDoesNotExist(keyId)
      val spec = buildKeyGenSpec(keyId, requireBiometrics, invalidateOnNewBiometric)
      val securityLevel = generateWithStrongBoxFallback(spec)
      publicKeyResult(keyId, securityLevel)
    }

    AsyncFunction("sign") { keyId: String, dataBase64: String, _: String ->
      val privateKey = findRequiredKey(keyId)
      val data = decodeBase64(dataBase64)
      val digest = hashSHA256(data)
      val derSignature = createSignature(privateKey, digest, keyId)
      val rawSignature = convertDERToRawRS(derSignature)
      encodeBase64(rawSignature)
    }

    AsyncFunction("getPublicKey") { keyId: String ->
      ensureKeyExists(keyId)
      val securityLevel = getSecurityLevel(keyId)
      publicKeyResult(keyId, securityLevel)
    }

    AsyncFunction("keyExists") { keyId: String ->
      keyStore.containsAlias(keyId)
    }

    AsyncFunction("deleteKey") { keyId: String ->
      if (keyStore.containsAlias(keyId)) {
        keyStore.deleteEntry(keyId)
      }
    }

    AsyncFunction("isHardwareBackedAvailable") {
      Build.VERSION.SDK_INT >= Build.VERSION_CODES.M
    }
  }

  // region Key lifecycle

  private fun ensureKeyDoesNotExist(keyId: String) {
    if (keyStore.containsAlias(keyId)) {
      throw ModuleException(ErrorCode.KEY_ALREADY_EXISTS, "Key '$keyId' already exists")
    }
  }

  private fun ensureKeyExists(keyId: String) {
    if (!keyStore.containsAlias(keyId)) {
      throw ModuleException(ErrorCode.KEY_NOT_FOUND, "Key '$keyId' not found")
    }
  }

  private fun buildKeyGenSpec(
    keyId: String,
    requireBiometrics: Boolean,
    invalidateOnNewBiometric: Boolean,
  ): KeyGenParameterSpec.Builder {
    val spec = KeyGenParameterSpec.Builder(
      keyId,
      KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY,
    )
      .setAlgorithmParameterSpec(java.security.spec.ECGenParameterSpec("secp256r1"))
      .setDigests(KeyProperties.DIGEST_SHA256)

    if (requireBiometrics) {
      spec.setUserAuthenticationRequired(true)
      if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
        spec.setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
      }
      if (invalidateOnNewBiometric) {
        spec.setInvalidatedByBiometricEnrollment(true)
      }
    }

    return spec
  }

  /** Try StrongBox first, fall back to TEE. Returns the security level string. */
  private fun generateWithStrongBoxFallback(spec: KeyGenParameterSpec.Builder): String {
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
      try {
        spec.setIsStrongBoxBacked(true)
        generateECKeyPair(spec.build())
        return "secure-enclave"
      } catch (_: StrongBoxUnavailableException) {
        spec.setIsStrongBoxBacked(false)
      }
    }
    generateECKeyPair(spec.build())
    return "trusted-execution"
  }

  private fun generateECKeyPair(spec: KeyGenParameterSpec) {
    KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore").run {
      initialize(spec)
      generateKeyPair()
    }
  }

  // endregion

  // region Signing

  private fun findRequiredKey(keyId: String): java.security.Key {
    if (!keyStore.containsAlias(keyId)) {
      throw ModuleException(ErrorCode.KEY_NOT_FOUND, "Key '$keyId' not found")
    }
    return keyStore.getKey(keyId, null)
      ?: throw ModuleException(ErrorCode.KEY_NOT_FOUND, "Key '$keyId' not found in KeyStore")
  }

  private fun decodeBase64(input: String): ByteArray =
    Base64.decode(input, Base64.DEFAULT)

  private fun hashSHA256(data: ByteArray): ByteArray =
    MessageDigest.getInstance("SHA-256").digest(data)

  private fun createSignature(key: java.security.Key, digest: ByteArray, keyId: String): ByteArray {
    return try {
      Signature.getInstance("NONEwithECDSA").run {
        initSign(key)
        update(digest)
        sign()
      }
    } catch (_: KeyPermanentlyInvalidatedException) {
      throw ModuleException(ErrorCode.KEY_INVALIDATED, "Key '$keyId' was invalidated (new biometric enrolled)")
    } catch (_: UserNotAuthenticatedException) {
      throw ModuleException(ErrorCode.BIOMETRIC_CANCELLED, "User not authenticated")
    } catch (e: Exception) {
      throw mapSigningException(e, keyId)
    }
  }

  private fun convertDERToRawRS(derSignature: ByteArray): ByteArray {
    return derToRawRS(derSignature)
      ?: throw ModuleException(ErrorCode.UNKNOWN, "Failed to parse DER signature")
  }

  private fun encodeBase64(data: ByteArray): String =
    Base64.encodeToString(data, Base64.NO_WRAP)

  // endregion

  // region Public key export

  private fun exportCompressedPublicKey(keyId: String): ByteArray {
    val ecPub = keyStore.getCertificate(keyId).publicKey as? ECPublicKey
      ?: throw ModuleException(ErrorCode.UNKNOWN, "Key '$keyId' is not an EC key")
    return compressECPublicKey(ecPub)
  }

  private fun publicKeyResult(keyId: String, securityLevel: String): Map<String, String> {
    val compressed = exportCompressedPublicKey(keyId)
    return mapOf(
      "publicKeyBase64" to encodeBase64(compressed),
      "securityLevel" to securityLevel,
    )
  }

  // endregion

  // region Security level

  private fun getSecurityLevel(keyId: String): String {
    return try {
      val key = keyStore.getKey(keyId, null) ?: return "software"
      val factory = KeyFactory.getInstance(key.algorithm, "AndroidKeyStore")
      val keyInfo = factory.getKeySpec(key, KeyInfo::class.java)
      if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
        when (keyInfo.securityLevel) {
          KeyProperties.SECURITY_LEVEL_STRONGBOX -> "secure-enclave"
          KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> "trusted-execution"
          else -> "software"
        }
      } else {
        @Suppress("DEPRECATION")
        if (keyInfo.isInsideSecureHardware) "trusted-execution" else "software"
      }
    } catch (_: Exception) {
      "software"
    }
  }

  // endregion

  // region Error mapping

  private fun mapSigningException(e: Exception, keyId: String): ModuleException {
    val msg = e.message ?: ""
    return when {
      msg.contains("cancel", ignoreCase = true) ->
        ModuleException(ErrorCode.BIOMETRIC_CANCELLED, "User cancelled authentication")
      msg.contains("lockout", ignoreCase = true) ->
        ModuleException(ErrorCode.BIOMETRIC_LOCKOUT, "Too many failed attempts — biometric locked")
      msg.contains("not enrolled", ignoreCase = true) ->
        ModuleException(ErrorCode.BIOMETRIC_NOT_ENROLLED, "No biometrics enrolled on device")
      else ->
        ModuleException(ErrorCode.UNKNOWN, e.localizedMessage ?: "Unknown error")
    }
  }

  // endregion
}
