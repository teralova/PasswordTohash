import re  #mengimpor modul RegEx (Regular Expressions) untuk memeriksa pola teks
import bcrypt  #mengimpor modul bcrypt untuk melakukan hashing password secara aman


def cek_kekuatan_password(password):
    """Fungsi untuk mengevaluasi seberapa kuat password berdasarkan kriteria standar keamanan."""
    skor = 0  #Variabel awal untuk menampung skor kekuatan password
    masukan = []  #List untuk menampung saran perbaikan jika password kurang kuat

    # 1. Cek Panjang Password
    if len(password) >= 8:
        skor += 1  #tambah skor 1 jika panjangnya minimal 8 karakter
    else:
        masukan.append("Panjang password minimal 8 karakter.")

    # 2. Cek Huruf Besar (Uppercase)
    if re.search(r"[A-Z]", password):
        skor += 1  #tambah skor 1 jika mengandung setidaknya satu huruf kapital
    else:
        masukan.append("Gunakan setidaknya satu huruf besar (A-Z).")

    # 3. Cek Huruf Kecil (Lowercase)
    if re.search(r"[a-z]", password):
        skor += 1  #tambah skor 1 jika mengandung setidaknya satu huruf kecil
    else:
        masukan.append("Gunakan setidaknya satu huruf kecil (a-z).")

    # 4. Cek Angka (Digit)
    if re.search(r"\d", password):
        skor += 1  #tambah skor 1 jika mengandung setidaknya satu angka
    else:
        masukan.append("Gunakan setidaknya satu angka (0-9).")

    # 5. Cek Karakter Spesial (Simbol)
    if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        skor += 1  #tambah skor 1 jika mengandung setidaknya satu karakter simbol
    else:
        masukan.append(
            "Gunakan setidaknya satu karakter khusus/simbol (!@#$%^&* dll)."
        )

    #menentukan Kategori Kekuatan Berdasarkan Total Skor (Skala 0-5)
    if skor == 5:
        kategori = "Sangat Kuat (Very Strong)"
    elif skor >= 3:
        kategori = "Sedang (Moderate)"
    else:
        kategori = "Lemah (Weak)"

    return kategori, masukan  #mengembalikan hasil kategori dan daftar saran


def buat_hash_bcrypt(password):
    """Fungsi untuk mengubah password teks biasa menjadi hash bcrypt yang aman."""
    #Bcrypt membutuhkan input dalam bentuk bytes, jadi string password di-encode ke utf-8
    password_bytes = password.encode("utf-8")

    #membuat 'salt' acak secara otomatis menggunakan gen-salt bawaan bcrypt
    salt = bcrypt.gensalt()

    #meng-hash password menggunakan salt yang sudah dibuat
    hashed_password = bcrypt.hashpw(password_bytes, salt)

    #mengembalikan hasil hash yang di-decode kembali ke string agar mudah dibaca/disimpan
    return hashed_password.decode("utf-8")


def main():
    """Fungsi utama untuk menjalankan alur program."""
    print("=== SIMPLE PASSWORD STRENGTH CHECKER & BCRYPT HASH GENERATOR ===")

    #mengambil masukan password dari pengguna
    password_input = input("\nMasukkan password yang ingin diuji: ")

    if not password_input:
        print("[ERROR] Password tidak boleh kosong!")
        return

    # 1. Jalankan Pemeriksaan Kekuatan Password
    kategori, masukan = cek_kekuatan_password(password_input)

    print("\n--- HASIL ANALISIS KEKUATAN ---")
    print(f"Status Kekuatan : {kategori}")

    #tampilkan saran jika password belum mencapai kriteria 'Sangat Kuat'
    if masukan:
        print("Saran Perbaikan :")
        for poin in masukan:
            print(f" - {poin}")

    # 2. Generate Hash Bcrypt
    print("\n--- HASIL HASHING BCRYPT ---")
    hash_result = buat_hash_bcrypt(password_input)
    print(f"Bcrypt Hash     : {hash_result}")
    print(
        "\n[INFO] Hash di atas aman disimpan di database karena menggunakan algoritma satu arah + salt."
    )


if __name__ == "__main__":
    main() 