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
 */
class Secrets(private val masterKeyAlias: String, private val prefs: SharedPreferences) {
    /**
     * Secrets uses the AndroidKeyStore to store key material. This ensures that the key material
     * never enters the Application's process space during crypto operations.
     */
    private val keyStore = KeyStore.getInstance(androidKeyStoreName).apply {
        load(null)
    }

    private val secureRandom: SecureRandom
        get() {
            return SecureRandom()
        }

    fun put(key: String, secret: String) {
        if (isEncrypted) {
            prefs.edit().putString(key, seal(secret)).commit()
        } else {
            prefs.edit().putString("${key}_unencrypted", secret).commit()
        }
    }

    @Synchronized
    fun get(key: String): String? {
        val unencryptedKey = "${key}_unencrypted"
        val unencryptedSecret = prefs.getString(unencryptedKey, null)
        if (!isEncrypted) {
            return unencryptedSecret
        }
        if (unencryptedSecret != null) {
            // encrypt secret and remove unencrypted
            put(key, unencryptedSecret)
            prefs.edit().putString(unencryptedKey, null).commit()
            return unencryptedSecret
        }
        return prefs.getString(key, null)?.let { unseal(it) }
    }

    @Synchronized
    fun get(key: String, defaultSecretLength: Int): String {
        val result = get(key)
        if (result != null) {
            return result
        }
        val newBytes = ByteArray(defaultSecretLength)
        secureRandom.nextBytes(newBytes)
        val newResult = Base64.encodeToString(newBytes, Base64.NO_WRAP or Base64.NO_PADDING)
        put(key, newResult)
        return newResult
    }

    /**
     * Indicates whether or not these secrets are encrypted.
     */
    private val isEncrypted: Boolean
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
    fun seal(plainText: String): String {
        return Base64.encodeToString(
            doSeal(plainText.toByteArray(Charset.defaultCharset())),
            Base64.DEFAULT
        )
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    fun unseal(cipherText: String): String {
        return doUnseal(
            Base64.decode(
                cipherText,
                Base64.DEFAULT
            )
        ).toString(Charset.defaultCharset())
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
    }
}
