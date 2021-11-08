package io.lantern.secrets

import android.content.SharedPreferences
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import androidx.annotation.RequiresApi
import java.nio.charset.Charset
import java.security.KeyStore
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * This exception indicates that a requested secret was still stored in the old insecure
 * string-based format. You can resolve this by calling regenerate() or update().
 */
class InsecureSecretException(
    private val secrets: Secrets,
    private val key: String,
    val secret: String
) :
    Exception("Detected insecure secret, recommend updating or regenerating secret.") {
    // regenerates the secret as a random secret of the specified byte length
    fun regenerate(length: Int): ByteArray {
        val newSecret = Secrets.generate(length)
        update(newSecret)
        return newSecret
    }

    // updates this secre with the newSecret
    fun update(newSecret: ByteArray) {
        secrets.put(key, newSecret)
    }
}

/**
 * Provides a mechanism for securely managing secrets stored in SharedPreferences. On Android M(23)
 * and above, values are encrypted using AES256 GCM. On older versions of Android that don't support
 * AES256 GCM natively, secrets are not encrypted at all.
 *
 * Key paths for encrypted values are automatically suffixed with "_unencrypted" whereas
 * encrypted values are always stored at bare paths.
 *
 * @param masterKeyAlias the name of the AES/GCM master key in the Android Key Store. Secrets will
 *        automatically generate a master key if necessary
 * @param prefs the SharedPreferences in which to store secrets
 * @param prefs legacyPrefs the SharedPreferences where secrets used to be stored using the older
 *              less secure version of Secrets (if implementing this in a system that had already
 *              used the original version)
 */
class Secrets(
    private val masterKeyAlias: String,
    private val prefs: SharedPreferences,
    private val legacyPrefs: SharedPreferences? = null
) {
    /**
     * Secrets uses the AndroidKeyStore to store key material. This ensures that the key material
     * never enters the Application's process space during crypto operations.
     */
    private val keyStore = KeyStore.getInstance(androidKeyStoreName).apply {
        load(null)
    }

    fun put(key: String, secret: ByteArray) {
        if (isEncrypted) {
            prefs.edit().putString(key, seal(secret)).commit()
            // clear value from legacy preferences just in case it was still in there
            legacyPrefs?.edit()?.putString(key, null)?.commit()
        } else {
            prefs.edit().putString("${key}_unencrypted", toBase64(secret)).commit()
        }
    }

    @Throws(InsecureSecretException::class)
    @Synchronized
    fun get(key: String): ByteArray? {
        val unencryptedKey = "${key}_unencrypted"
        val _unencryptedSecret = prefs.getString(unencryptedKey, null) ?: run {
            val legacyUnencryptedSecret = legacyPrefs?.getString(unencryptedKey, null)
            if (legacyUnencryptedSecret != null) {
                legacyPrefs?.edit()?.putString(unencryptedKey, null)?.commit()
                prefs.edit().putString(unencryptedKey, null).commit()
            }
            legacyUnencryptedSecret
        }
        val unencryptedSecret = _unencryptedSecret?.let { fromBase64(it) }
        if (!isEncrypted) {
            return unencryptedSecret
        }
        if (unencryptedSecret != null) {
            // encrypt secret and remove unencrypted
            put(key, unencryptedSecret)
            prefs.edit().putString(unencryptedKey, null).commit()
            return unencryptedSecret
        }
        return prefs.getString(key, null)?.let { unseal(it) } ?: run {
            val legacyPlainText = legacyPrefs
                ?.getString(key, null)
                ?.let { legacyUnseal(it) }
            if (legacyPlainText != null) {
                throw InsecureSecretException(this, key, legacyPlainText)
            }
            null
        }
    }

    @Throws(InsecureSecretException::class)
    @Synchronized
    fun get(key: String, defaultSecretLength: Int): ByteArray {
        val result = get(key)
        if (result != null) {
            return result
        }
        val newResult = generate(defaultSecretLength)
        put(key, newResult)
        return newResult
    }

    /**
     * Indicates whether or not these secrets are encrypted.
     */
    internal val isEncrypted: Boolean
        get() {
            return Build.VERSION.SDK_INT >= Build.VERSION_CODES.M
        }

    @RequiresApi(api = Build.VERSION_CODES.M)
    @Synchronized
    private fun getMasterKey(): SecretKey {
        return keyStore.getKey(masterKeyAlias, CharArray(0)) as SecretKey? ?: genMasterKey()
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    fun genMasterKey(): SecretKey {
        val keyGen = KeyGenerator.getInstance("AES", "AndroidKeyStore")
        val parameterSpec =
            KeyGenParameterSpec.Builder(
                masterKeyAlias,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setKeySize(256)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .build()
        keyGen.init(parameterSpec)
        return keyGen.generateKey()
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    fun seal(plainText: ByteArray): String {
        return toBase64(doSeal(plainText))
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    internal fun legacySeal(plainText: String): String {
        return seal(plainText.toByteArray(Charset.defaultCharset()))
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    internal fun unseal(cipherText: String): ByteArray {
        return doUnseal(fromBase64(cipherText))
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    internal fun legacyUnseal(cipherText: String): String {
        return unseal(cipherText).toString(Charset.defaultCharset())
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    fun doSeal(plainText: ByteArray): ByteArray {
        val cipher = Cipher.getInstance(cipherName)
        cipher.init(Cipher.ENCRYPT_MODE, getMasterKey(), secureRandom)
        val cipherText = cipher.doFinal(plainText)
        return cipher.iv + cipherText
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    fun doUnseal(sealed: ByteArray): ByteArray {
        val iv = sealed.copyOf(12)
        val cipherText = sealed.copyOfRange(12, sealed.size)
        val cipher = Cipher.getInstance(cipherName)
        cipher.init(Cipher.DECRYPT_MODE, getMasterKey(), GCMParameterSpec(128, iv))
        return cipher.doFinal(cipherText)
    }

    companion object {
        private const val androidKeyStoreName = "AndroidKeyStore"
        private const val cipherName = "AES/GCM/NoPadding"
        internal const val base64EncodingStyle = Base64.NO_WRAP or Base64.NO_PADDING

        fun toBase64(bytes: ByteArray): String = Base64.encodeToString(bytes, base64EncodingStyle)

        fun fromBase64(str: String): ByteArray = Base64.decode(str, base64EncodingStyle)

        /**
         * Generates a random secret of the given byte length.
         */
        fun generate(length: Int): ByteArray {
            val bytes = ByteArray(length)
            secureRandom.nextBytes(bytes)
            return bytes
        }

        private val secureRandom: SecureRandom
            get() {
                return SecureRandom()
            }
    }
}
