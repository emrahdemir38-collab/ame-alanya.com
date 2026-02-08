# APK - Kullanıcı Adı/Şifre Oto-Doldurma Rehberi

## 🔴 Sorun
APK'da her giriş yaptığında kullanıcı adı ve şifre yazılması gerekiyor.

## ✅ Çözüm (Kodular'da Uygulanacak)

### **Adım 1: TinyDB Componenti Ekle**
1. Kodular editörü aç
2. **Designer** sekmesine git
3. Sağ panelde **Storage** bölümünü bul
4. **TinyDB** componentini drag-drop et

### **Adım 2: Login Screen'de Kayıt Kodu**

**Login Buttonunun `Click` event'ine ekle:**

```
when LoginButton.Click
  call API (api/login) with username ve password
  
  IF response.success THEN
    IF RememberCheckbox.Checked THEN
      call TinyDB.StoreValue(tag="user_prefs", valueKey="username", value=UsernameInput.Text)
      call TinyDB.StoreValue(tag="user_prefs", valueKey="password", value=PasswordInput.Text)
      call TinyDB.StoreValue(tag="user_prefs", valueKey="auto_login", value=true)
    END
    
    open StudentDashboardScreen
  END
```

### **Adım 3: App Başlangıçında Oto-Doldur**

**Screen1.Initialize event'ine ekle:**

```
when Screen1.Initialize
  set username to TinyDB.GetValue(tag="user_prefs", valueKey="username", default="")
  set password to TinyDB.GetValue(tag="user_prefs", valueKey="password", default="")
  set auto_login to TinyDB.GetValue(tag="user_prefs", valueKey="auto_login", default=false)
  
  IF auto_login AND username ≠ "" AND password ≠ "" THEN
    set UsernameInput.Text to username
    set PasswordInput.Text to password
    set RememberCheckbox.Checked to true
    
    VEYA direkt login yap:
    call LoginAPI with username and password
    IF success THEN
      open StudentDashboardScreen
    END
  END
```

### **Adım 4: Logout'ta Temizle**

**Logout Buttonun Click event'ine ekle:**

```
when LogoutButton.Click
  call TinyDB.DeleteValue(tag="user_prefs", valueKey="username")
  call TinyDB.DeleteValue(tag="user_prefs", valueKey="password")
  call TinyDB.DeleteValue(tag="user_prefs", valueKey="auto_login")
  
  open LoginScreen
```

---

## 🔒 Güvenlik Notları

- Şu anki yöntem basit ama local depolama kullanıyor
- Daha güvenli için: **FirebaseDB** kullanıp remote depolama yapabilirsin
- Veya Android'in **EncryptedSharedPreferences** kullanabilirsin (native)

---

## 📦 Alternatif: Firebase kullanarak

```
when LoginButton.Click
  call Firebase.SetValue(path="/users/" + username, value=password)
  
when Screen1.Initialize
  call Firebase.GetValue(path="/users/" + LastUsername)
  set PasswordInput to retrieved value
```

---

## 🎯 Sonuç
Adımları tamamladıktan sonra:
- ✅ Şifremi Kaydet işaretliyse → bilgiler kaydedilir
- ✅ Uygulama açılınca → bilgiler otomatik doldurulur
- ✅ Logout → bilgiler silinir
