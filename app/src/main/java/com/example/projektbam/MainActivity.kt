package com.example.projektbam

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Environment
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import android.view.Menu
import android.view.MenuItem
import android.view.WindowManager
import android.widget.*
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import com.google.android.material.textfield.TextInputEditText
import java.io.*
import java.net.URLConnection
import java.nio.charset.Charset
import java.security.KeyStore
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec


class MainActivity : AppCompatActivity() {
    private lateinit var buttonSaveMessage: Button
    private lateinit var buttonReadMessage: Button

    private lateinit var textInput: TextInputEditText

    private lateinit var ks: KeyStore
    private lateinit var secretKey: SecretKey

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        checkDeviceSecurityAndNotifyIfViolated()

        initializeAndroidKeyStore()

        val toolbar = findViewById<androidx.appcompat.widget.Toolbar>(R.id.toolbar)
        setSupportActionBar(toolbar)

        textInput = findViewById(R.id.textInput)

        initializeButtons()
    }

    override fun onCreateOptionsMenu(menu: Menu?): Boolean {
        menuInflater.inflate(R.menu.main_menu, menu)
        return true
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        val id: Int = item.itemId

        when (id) {
            R.id.buttonExport -> {
                exportData()
                return true
            }

            R.id.buttonImport -> {
                importData()
                return true
            }

            R.id.buttonWipe -> {
                wipeData()
                return true
            }
        }
        return super.onOptionsItemSelected(item)
    }

    private fun initializeButtons() {
        buttonSaveMessage = findViewById(R.id.buttonSave)
        buttonReadMessage = findViewById(R.id.buttonRead)

        buttonSaveMessage.setOnClickListener {
            saveAction()
            return@setOnClickListener
        }

        buttonReadMessage.setOnClickListener {
            readAction()
            return@setOnClickListener
        }
    }

    private fun exportData() {
        val data = textInput.text.toString()

        var password: String
        var fileName: String

        val dialogView = layoutInflater.inflate(R.layout.dialog, null)
        val inputFileName = dialogView.findViewById<EditText>(R.id.inputFileName)
        val inputPassword = dialogView.findViewById<EditText>(R.id.inputPassword)
        val confirmButton = dialogView.findViewById<Button>(R.id.confirmButton)
        confirmButton.text = getString(EXPORT_DATA_MESSAGE_ID)

        val dialog = AlertDialog.Builder(this)
            .setTitle(PROVIDE_PASSWORD_MESSAGE_ID)
            .setView(dialogView)
            .create()

        confirmButton.setOnClickListener {
            password = inputPassword.text.toString()
            fileName = inputFileName.text.toString()
            dialog.dismiss()

            if (password.isBlank() || fileName.isBlank()) {
                makeToast(getString(BLANK_PASSWORD_OR_FILENAME_MESSAGE_ID))
                return@setOnClickListener
            }

            if (!fileName.endsWith(".txt")) fileName = "$fileName.txt"

            val documents = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOCUMENTS)
            val file = File(documents,  fileName)

            try {
                val salt = ByteArray(16)
                SecureRandom().nextBytes(salt)
                val iv = ByteArray(16)
                SecureRandom().nextBytes(iv)

                val secretKey = generateSecretKey(password, salt)
                val cipher = Cipher.getInstance(EXPORT_IMPORT_ALGORITHM)
                val ivSpec = IvParameterSpec(iv)
                cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec)
                val encryptedData = cipher.doFinal(data.toByteArray(Charset.forName(CHAR_SET)))

                val outputStream = ByteArrayOutputStream()
                outputStream.write(salt)
                outputStream.write(iv)
                outputStream.write(encryptedData)
                val encryptedBytes = outputStream.toByteArray()

                FileOutputStream(file).write(encryptedBytes)
                makeToast(getString(DATA_EXPORTED_SUCCESSFULLY_MESSAGE_ID))
            } catch (e: Exception) {
                makeToast(getString(ENCRYPTION_FAILED_MESSAGE_ID))
            }

            triggerMediaScanner(file)
        }

        dialog.show()
    }

    private fun importData() {
        var password: String
        var fileName: String
        val dialogView = layoutInflater.inflate(R.layout.dialog, null)
        val inputFileName = dialogView.findViewById<EditText>(R.id.inputFileName)
        val inputPassword = dialogView.findViewById<EditText>(R.id.inputPassword)
        val confirmButton = dialogView.findViewById<Button>(R.id.confirmButton)
        confirmButton.text = getString(IMPORT_DATA_MESSAGE_ID)

        val dialog = AlertDialog.Builder(this)
            .setTitle(PROVIDE_PASSWORD_MESSAGE_ID)
            .setView(dialogView)
            .create()

        confirmButton.setOnClickListener {
            password = inputPassword.text.toString()
            fileName = inputFileName.text.toString()
            dialog.dismiss()

            if (password.isBlank() || fileName.isBlank()) {
                makeToast(getString(BLANK_PASSWORD_OR_FILENAME_MESSAGE_ID))
                return@setOnClickListener
            }

            if (!fileName.endsWith(".txt")) fileName = "$fileName.txt"

            //read file
            val documents = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOCUMENTS)
            val file = File(documents, fileName)
            try {
                val fileBytes = FileInputStream(file).readBytes()
                val salt = fileBytes.copyOfRange(0, 16)
                val iv = fileBytes.copyOfRange(16, 32)
                val encryptedData = fileBytes.copyOfRange(32, fileBytes.size)

                val secretKey = generateSecretKey(password, salt)
                val cipher = Cipher.getInstance(EXPORT_IMPORT_ALGORITHM)
                val ivSpec = IvParameterSpec(iv)
                cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec)
                val decryptedData = cipher.doFinal(encryptedData)

                textInput.setText(String(decryptedData, Charset.forName(CHAR_SET)))
                makeToast(getString(DATA_IMPORTED_SUCCESSFULLY_MESSAGE_ID))
            } catch (e: Exception) {
                makeToast(getString(DECRYPTION_FAILED_MESSAGE_ID))
            }
        }

        dialog.show()
    }

    private fun initializeAndroidKeyStore() {
        val specBuilder = KeyGenParameterSpec.Builder(
            KEY_STORE_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setUserAuthenticationRequired(true)
            .setInvalidatedByBiometricEnrollment(true)
            .setKeySize(256)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            specBuilder.setUserAuthenticationParameters(0, KeyProperties.AUTH_DEVICE_CREDENTIAL)
        }

        val spec = specBuilder.build()

        ks = KeyStore.getInstance(KEY_STORE_TYPE)
        ks.load(null)

        if (!ks.containsAlias(spec.keystoreAlias)) {
            val keyGenerator: KeyGenerator = KeyGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_AES,
                KEY_STORE_TYPE
            )
            keyGenerator.init(spec)
            keyGenerator.generateKey()
        }

        val secretKeyEntry = ks.getEntry(KEY_STORE_ALIAS, null) as KeyStore.SecretKeyEntry
        secretKey = secretKeyEntry.secretKey
    }

    private fun readAction() {
        checkKeyExists()

        val file = File(applicationContext.getExternalFilesDir(null), DATA_FILE_NAME)
        if (!file.exists()) {
            makeToast(getString(NO_FILE_MESSAGE_ID))
            Log.d(APPLICATION_TAG, getString(NO_FILE_MESSAGE_ID))
            return
        }

        FileInputStream(file).use { fis ->
            val ivSize = fis.read()
            val iv = ByteArray(ivSize)
            fis.read(iv, 0, ivSize)
            val encryptedData = fis.readBytes()

            val cipher = Cipher.getInstance(ALGORITHM).apply {
                val gcmSpec = GCMParameterSpec(128, iv)
                init(Cipher.DECRYPT_MODE, secretKey, gcmSpec)
            }

            authenticate(
                reason = getString(READ_FROM_FILE_MESSAGE_ID),
                onSuccess = { textInput.setText(String(cipher.doFinal(encryptedData), Charset.defaultCharset())) },
                cipher = cipher
            )
        }
    }

    private fun saveAction() {
        handlePermissions()
        checkKeyExists()

        val inputString = textInput.text.toString()

        if (inputString.isBlank()) {
            makeToast(getString(BLANK_DATA_MESSAGE_ID))
            Log.i(APPLICATION_TAG, getString(BLANK_DATA_MESSAGE_ID))
            return
        }

        val file = File(applicationContext.getExternalFilesDir(null), DATA_FILE_NAME)
        if (file.exists()) {
            file.delete()
        }

        val cipher = Cipher.getInstance(ALGORITHM).apply {
            init(Cipher.ENCRYPT_MODE, secretKey)
        }

        val inputByteArray = inputString.toByteArray(Charset.defaultCharset())

        authenticate(
            reason = getString(WRITE_TO_FILE_MESSAGE_ID),
            onSuccess = { saveToFile(inputByteArray, cipher, file) },
            cipher = cipher,
        )
    }

    private fun wipeData() {
        handlePermissions()

        authenticate(
            reason = getString(CLEAR_MEMORY_MESSAGE_ID),
            onSuccess = { clearData() },
            cipher = null,
        )
    }

    private fun saveToFile(data: ByteArray, cipher: Cipher, file: File) {
        val encryptedData = cipher.doFinal(data)
        FileOutputStream(file).use { fos ->
            fos.write(cipher.iv.size)
            fos.write(cipher.iv)
            fos.write(encryptedData)
        }
    }

    private fun generateSecretKey(password: String, salt: ByteArray): SecretKeySpec {
        val factory = SecretKeyFactory.getInstance(SECRET_KEY_ALGORITHM)
        val spec = PBEKeySpec(password.toCharArray(), salt, 65536, 256)
        val tmp = factory.generateSecret(spec)
        return SecretKeySpec(tmp.encoded, AES_ALGORITHM)
    }

    private fun authenticate(reason: String, onSuccess: () -> Unit, cipher: Cipher?) {
        val executor = ContextCompat.getMainExecutor(this)
        val biometricPrompt = BiometricPrompt(this, executor, object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                super.onAuthenticationSucceeded(result)
                Log.d(APPLICATION_TAG, getString(AUTH_SUCCESS_MESSAGE_ID))
                onSuccess()
            }
        })

        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle(getString(BIOMETRIC_TITLE_MESSAGE_ID))
            .setSubtitle(reason)
            .setAllowedAuthenticators(BiometricManager.Authenticators.DEVICE_CREDENTIAL)
            .build()

        if (cipher == null) {
            biometricPrompt.authenticate(promptInfo)
        } else {
            biometricPrompt.authenticate(promptInfo, BiometricPrompt.CryptoObject(cipher))
        }
    }

    private fun checkKeyExists() {
        ks = KeyStore.getInstance(KEY_STORE_TYPE)
        ks.load(null)
        if (!ks.containsAlias(KEY_STORE_ALIAS)) {
            initializeAndroidKeyStore()
        }
    }

    private fun clearData() {
        val file = File(applicationContext.getExternalFilesDir(null), DATA_FILE_NAME)
        if (file.exists()) {
            file.delete()
        }

        textInput.clearComposingText()
        textInput.text?.clear()

        try {
            ks = KeyStore.getInstance(KEY_STORE_TYPE)
            ks.load(null)
            if (ks.containsAlias(KEY_STORE_ALIAS)) {
                ks.deleteEntry(KEY_STORE_ALIAS)
                makeToast(getString(DATA_WIPED_MESSAGE_ID))
                Log.i(APPLICATION_TAG, getString(DATA_WIPED_MESSAGE_ID))
            } else {
                makeToast(getString(NO_KEY_TO_DELETE_MESSAGE_ID))
                Log.w(APPLICATION_TAG, getString(NO_KEY_TO_DELETE_MESSAGE_ID))
            }
        } catch (e: Exception) {
            makeToast(getString(ERROR_DELETE_KEY_MESSAGE_ID))
            Log.e(APPLICATION_TAG, getString(ERROR_DELETE_KEY_MESSAGE_ID), e)
        }
    }

    private fun handlePermissions() {
        if (ContextCompat.checkSelfPermission(applicationContext, Manifest.permission.WRITE_EXTERNAL_STORAGE)
            != PackageManager.PERMISSION_GRANTED) {
            ActivityCompat.requestPermissions(
                this@MainActivity,
                arrayOf(Manifest.permission.WRITE_EXTERNAL_STORAGE),
                REQUEST_CODE
            )
        }
    }

    private fun checkDeviceSecurityAndNotifyIfViolated() {
        if (isDeviceRooted() || isFridaServerRunning()) {
            makeToast(getString(INSECURE_DEVICE_MESSAGE_ID))
            Log.w(APPLICATION_TAG, getString(INSECURE_DEVICE_MESSAGE_ID))
        }
    }

    private fun isDeviceRooted(): Boolean {
        val paths = arrayOf(
            "/system/app/Superuser.apk",
            "/sbin/su", "/system/bin/su", "/system/xbin/su",
            "/data/local/xbin/su", "/data/local/bin/su",
            "/system/sd/xbin/su", "/system/bin/failsafe/su",
            "/data/local/su", "/su/bin/su"
        )

        paths.forEach { if (File(it).exists()) return true }

        try {
            Runtime.getRuntime().exec("su")
            return true
        } catch (_: Exception) {
        }

        return false
    }

    private fun isFridaServerRunning(): Boolean {
        try {
            val process = Runtime.getRuntime().exec("ps")
            val reader = BufferedReader(InputStreamReader(process.inputStream))
            var line: String?

            while (reader.readLine().also { line = it } != null) {
                if (line!!.contains("frida-server")) {
                    return true
                }
            }
        } catch (_: Exception) {
        }
        return false
    }

    private fun makeToast(message: String) =
        Toast.makeText(this.applicationContext, message, Toast.LENGTH_SHORT).show()

    private fun triggerMediaScanner(file: File) {
        //ten kod sprawia że widać w telefonie ten plik natychmiast
        val mimeType = URLConnection.guessContentTypeFromName(file.name)
        val mediaScanIntent = Intent(Intent.ACTION_MEDIA_SCANNER_SCAN_FILE)
        val contentUri = Uri.fromFile(file)
        mediaScanIntent.data = contentUri
        mediaScanIntent.putExtra(Intent.EXTRA_MIME_TYPES, mimeType)
        applicationContext.sendBroadcast(mediaScanIntent)
    }

    companion object {
        private const val REQUEST_CODE: Int = 222
        private const val DATA_FILE_NAME = "tajne.txt"
        private const val KEY_STORE_ALIAS = "file_encryption_master_key"
        private const val KEY_STORE_TYPE = "AndroidKeyStore"
        private const val APPLICATION_TAG = "BAM"
        private const val ALGORITHM = "AES/GCM/NoPadding"
        private const val EXPORT_IMPORT_ALGORITHM = "AES/CBC/PKCS5Padding"
        private const val AES_ALGORITHM = "AES"
        private const val SECRET_KEY_ALGORITHM = "PBKDF2WithHmacSHA256"
        private const val CHAR_SET = "UTF-8"

        private const val INSECURE_DEVICE_MESSAGE_ID = R.string.insecure_device_message
        private const val DATA_WIPED_MESSAGE_ID = R.string.data_wiped
        private const val NO_KEY_TO_DELETE_MESSAGE_ID = R.string.no_key_to_delete
        private const val ERROR_DELETE_KEY_MESSAGE_ID = R.string.error_delete_key
        private const val BLANK_DATA_MESSAGE_ID = R.string.blank_data
        private const val NO_FILE_MESSAGE_ID = R.string.no_file
        private const val AUTH_SUCCESS_MESSAGE_ID = R.string.auth_success
        private const val BIOMETRIC_TITLE_MESSAGE_ID = R.string.biometric_title
        private const val DATA_IMPORTED_SUCCESSFULLY_MESSAGE_ID = R.string.data_imported_successfully
        private const val DECRYPTION_FAILED_MESSAGE_ID = R.string.decryption_failed
        private const val BLANK_PASSWORD_OR_FILENAME_MESSAGE_ID = R.string.blank_password_or_file_name
        private const val PROVIDE_PASSWORD_MESSAGE_ID = R.string.provide_password
        private const val DATA_EXPORTED_SUCCESSFULLY_MESSAGE_ID = R.string.data_exported_successfully
        private const val ENCRYPTION_FAILED_MESSAGE_ID = R.string.encryption_failed
        private const val WRITE_TO_FILE_MESSAGE_ID = R.string.write_to_file
        private const val READ_FROM_FILE_MESSAGE_ID = R.string.read_from_file
        private const val CLEAR_MEMORY_MESSAGE_ID = R.string.clear_memory
        private const val EXPORT_DATA_MESSAGE_ID = R.string.export_data
        private const val IMPORT_DATA_MESSAGE_ID = R.string.import_data
    }
}