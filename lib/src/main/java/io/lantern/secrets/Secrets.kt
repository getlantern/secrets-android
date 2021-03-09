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
import java.util.*
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Provides a mechanism for securely managing secrets stored in SharedPreferences. On Android M(23)
 * and above, keys and values are encrypted using AES256 GCM. On older versions of Android that
 * don't support AES256 GCM natively, secrets are not encrypted at all.
 *
 * @param masterKeyAlias the name of the AES/GCM master key in the Android Key Store. Secrets will
 *        automatically generate a master key if necessary
 * @param prefs the SharedPreferences in which to store secrets
 */
class Secrets(private val masterKeyAlias: String, private val prefs: SharedPreferences) {
    private val keyStore = KeyStore.getInstance("AndroidKeyStore").apply {
        load(null)
    }

    fun put(key: String, secret: String) {
        prefs.edit().putString("${key}_encrypted", sealIfNecessary(secret)).commit()
    }

    fun get(key: String): String? {
        val result = prefs.getString("${key}_encrypted", null)
        if (result != null) {
            return unsealIfNecessary(result)
        }
        // fall back to unencrypted value (for example if we've upgrade Android from a version that
        // doesn't support encryption to one that does.
        return prefs.getString(key, null)
    }

    @Synchronized
    fun get(key: String, defaultSecretLength: Int): String {
        val result = get(key)
        if (result != null) {
            return result
        }
        val newBytes = ByteArray(defaultSecretLength)
        SecureRandom.getInstance("SHA1PRNG").nextBytes(newBytes)
        val newResult = Base64.encodeToString(newBytes, Base64.DEFAULT)
        put(key, newResult)
        return newResult
    }

    /**
     * Indicates whether or not these secrets are encrypted.
     */
    val isEncrypted: Boolean
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

    fun sealIfNecessary(plainText: String): String {
        if (isEncrypted) {
            return Base64.encodeToString(
                seal(plainText.toByteArray(Charset.defaultCharset())),
                Base64.DEFAULT
            )
        } else {
            return plainText;
        }
    }

    fun unsealIfNecessary(cipherText: String): String {
        if (isEncrypted) {
            return unseal(
                Base64.decode(
                    cipherText,
                    Base64.DEFAULT
                )
            ).toString(Charset.defaultCharset())
        } else {
            return cipherText;
        }
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    fun seal(plainText: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, getMasterKey(), SecureRandom.getInstance("SHA1PRNG"))
        val cipherText = cipher.doFinal(plainText);
        return cipher.iv + cipherText
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    fun unseal(sealed: ByteArray): ByteArray {
        val iv = Arrays.copyOf(sealed, 12)
        val cipherText = Arrays.copyOfRange(sealed, 12, sealed.size)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, getMasterKey(), GCMParameterSpec(128, iv))
        return cipher.doFinal(cipherText)
    }
}