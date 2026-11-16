/*
 * LAB 01: SỐ NGUYÊN TỐ & TRAO ĐỔI KHÓA DIFFIE-HELLMAN (C++14)
 * 
 * - Tự cài đặt cấu trúc số lớn 512-bit (BigInt512).
 * - Cài đặt các thuật toán AddMod, MultMod, ExpMod dựa theo Pseudocode.
 * - Cài đặt kiểm tra nguyên tố Miller-Rabin & Sinh số nguyên tố an toàn (Safe Prime).
 * - Cài đặt giao thức Trao đổi khóa Diffie-Hellman cho Alice và Bob.
 */

#include <iostream>
#include <cstdint>
#include <random>
#include <iomanip>
#include "prng.h" 

// ============================================================================
// CẤU TRÚC DỮ LIỆU SỐ LỚN 512-BIT (BigInt512)
// Lưu trữ số nguyên không dấu 512-bit dưới dạng mảng 8 phần tử uint64_t.
// Biểu diễn Little-Endian: limbs lưu 64-bit thấp nhất (LSB), limbs[7] lưu MSB.
// ============================================================================

struct BigInt512 {
    static const int NUM_LIMBS = 8;
    uint64_t limbs[NUM_LIMBS] = {0};

    BigInt512() {
        for (int i = 0; i < NUM_LIMBS; ++i) limbs[i] = 0;
    }

    BigInt512(uint64_t val) {
        limbs[0] = val;
        for (int i = 1; i < NUM_LIMBS; ++i) limbs[i] = 0;
    }

    // Lấy bit thứ i (0 <= i < 512)
    bool get_bit(int i) const {
        if (i < 0 || i >= 512) return false;
        int limb_idx = i / 64;
        int bit_idx = i % 64;
        return (limbs[limb_idx] >> bit_idx) & 1ULL;
    }

    // Gán giá trị bit thứ i (0 <= i < 512)
    void set_bit(int i, bool val) {
        if (i < 0 || i >= 512) return;
        int limb_idx = i / 64;
        int bit_idx = i % 64;
        if (val) limbs[limb_idx] |= (1ULL << bit_idx);
        else     limbs[limb_idx] &= ~(1ULL << bit_idx);
    }

    // Kiểm tra số 0
    bool is_zero() const {
        for (int i = 0; i < NUM_LIMBS; ++i) {
            if (limbs[i] != 0) return false;
        }
        return true;
    }

    // Toán tử so sánh lớn hơn hoặc bằng (>=)
    bool operator>=(const BigInt512& other) const {
        for (int i = NUM_LIMBS - 1; i >= 0; --i) {
            if (limbs[i] > other.limbs[i]) return true;
            if (limbs[i] < other.limbs[i]) return false;
        }
        return true;
    }

    // Toán tử so sánh bằng (==)
    bool operator==(const BigInt512& other) const {
        for (int i = 0; i < NUM_LIMBS; ++i) {
            if (limbs[i] != other.limbs[i]) return false;
        }
        return true;
    }

    bool operator!=(const BigInt512& other) const {
        return !(*this == other);
    }

    bool operator<(const BigInt512& other) const {
        return !(*this >= other);
    }

    bool operator>(const BigInt512& other) const {
        return !(*this < other) && !(*this == other);
    }

    bool operator<=(const BigInt512& other) const {
        return (*this < other) || (*this == other);
    }

    // In biểu diễn Hex của số 512-bit
    void print_hex() const {
        std::cout << "0x";
        bool leading_zero = true;
        for (int i = NUM_LIMBS - 1; i >= 0; --i) {
            if (leading_zero && limbs[i] == 0 && i > 0) continue;
            if (leading_zero) {
                std::cout << std::hex << limbs[i];
                leading_zero = false;
            } else {
                std::cout << std::hex << std::setw(16) << std::setfill('0') << limbs[i];
            }
        }
        std::cout << std::dec;
    }
};

// Phép cộng 512-bit có truyền nhớ (carry)
BigInt512 add(const BigInt512& a, const BigInt512& b) {
    BigInt512 res;
    uint64_t carry = 0;
    for (int i = 0; i < BigInt512::NUM_LIMBS; ++i) {
        uint64_t sum = a.limbs[i] + b.limbs[i] + carry;
        if (carry == 0) {
            carry = (sum < a.limbs[i]) ? 1 : 0;
        } else {
            carry = (sum <= a.limbs[i]) ? 1 : 0;
        }
        res.limbs[i] = sum;
    }
    return res;
}

// Phép trừ 512-bit có truyền mượn (borrow) - Yêu cầu a >= b
BigInt512 subtract(const BigInt512& a, const BigInt512& b) {
    BigInt512 res;
    uint64_t borrow = 0;
    for (int i = 0; i < BigInt512::NUM_LIMBS; ++i) {
        uint64_t sub = a.limbs[i] - b.limbs[i] - borrow;
        if (borrow == 0) {
            borrow = (a.limbs[i] < b.limbs[i]) ? 1 : 0;
        } else {
            borrow = (a.limbs[i] <= b.limbs[i]) ? 1 : 0;
        }
        res.limbs[i] = sub;
    }
    return res;
}

// Dịch phải 1 bit (x >> 1)
BigInt512 shift_right_1(const BigInt512& val) {
    BigInt512 res;
    uint64_t carry = 0;
    for (int i = BigInt512::NUM_LIMBS - 1; i >= 0; --i) {
        uint64_t next_carry = val.limbs[i] & 1ULL;
        res.limbs[i] = (val.limbs[i] >> 1) | (carry << 63);
        carry = next_carry;
    }
    return res;
}

// ============================================================================
// CÁC THUẬT TOÁN PHÉP TOÁN MÔ-ĐUN (Theo pseudocode)
// ============================================================================

// 1. Phép cộng Mô-đun: (x + y) % p
BigInt512 AddMod(BigInt512 x, BigInt512 y, BigInt512 p) {
    BigInt512 p_minus_y = subtract(p, y);
    if (x >= p_minus_y) {
        return subtract(x, p_minus_y); // x - (p - y)
    }
    return add(x, y); // x + y
}

// 1.5. Hàm Modulo cơ bản
BigInt512 MOD(BigInt512 x, BigInt512 y) {
    BigInt512 rem(0);
    for (int i = 511; i >= 0; --i) {
        // rem = rem << 1
        BigInt512 temp = rem;
        uint64_t carry = 0;
        for(int j = 0; j < BigInt512::NUM_LIMBS; ++j) {
            uint64_t next_carry = temp.limbs[j] >> 63;
            rem.limbs[j] = (temp.limbs[j] << 1) | carry;
            carry = next_carry;
        }
        uint64_t overflow = carry; // Giữ lại bit tràn thứ 513
        
        // rem = rem + x_i
        if (x.get_bit(i)) {
            rem = add(rem, BigInt512(1));
        }
        
        // if rem >= y then rem = rem - y
        if (overflow || rem >= y) { // Sửa điều kiện tại đây
            rem = subtract(rem, y);
        }
    }
    return rem;
}

// 2. Phép nhân Mô-đun: (x * y) % p
BigInt512 MultMod(BigInt512 x, BigInt512 y, BigInt512 p) {
    BigInt512 ret(0);
    x = MOD(x, p); // Đảm bảo x < p
    for (int i = 0; i < 512; ++i) {
        if (y.get_bit(i)) {
            ret = AddMod(ret, x, p);
        }
        x = AddMod(x, x, p);
    }
    return ret;
}

// 3. Phép lũy thừa Mô-đun: (base^exponent) % p (modular_exponentiation)
BigInt512 ExpMod(BigInt512 base, BigInt512 exponent, BigInt512 p) {
    BigInt512 ret(1);
    base = MOD(base, p); // Sửa: Dùng hàm MOD vừa thêm ở trên
    for (int i = 0; i < 512; ++i) {
        if (exponent.get_bit(i)) {
            ret = MultMod(ret, base, p);
        }
        base = MultMod(base, base, p);
    }
    return ret;
}

BigInt512 modular_exponentiation(BigInt512 base, BigInt512 exponent, BigInt512 p) {
    return ExpMod(base, exponent, p);
}

// ============================================================================
// HÀM SINH SỐ NGẪU NHIÊN VÀ KIỂM TRA SỐ NGUYÊN TỐ MILLER-RABIN
// ============================================================================

// Sinh số ngẫu nhiên N-bit (mặc định 512-bit)
BigInt512 generate_random_512(PRNG& prng, int bit_size = 512) {
    BigInt512 res;
    // Điền 64 byte ngẫu nhiên (tương đương 512-bit) vào mảng limbs
    prng.random_bytes(reinterpret_cast<uint8_t*>(res.limbs), 64);

    res.set_bit(bit_size - 1, true); // Bit cao nhất bằng 1
    res.set_bit(0, true);            // Bit thấp nhất bằng 1 (số lẻ)
    for (int i = bit_size; i < 512; ++i) {
        res.set_bit(i, false);
    }
    return res;
}

// Thuật toán kiểm tra số nguyên tố Miller-Rabin
bool miller_rabin(BigInt512 n, PRNG& prng, int k_iterations = 10) {
    if (n <= BigInt512(1)) return false;
    if (n == BigInt512(2) || n == BigInt512(3)) return true;
    if (n.get_bit(0) == 0) return false;

    BigInt512 n_minus_1 = subtract(n, BigInt512(1));
    BigInt512 d = n_minus_1;
    int r = 0;
    while (d.get_bit(0) == 0) {
        d = shift_right_1(d);
        r++;
    }

    for (int i = 0; i < k_iterations; ++i) {
        BigInt512 a;
        // Lấy ngẫu nhiên phần tử 64-bit thấp nhất
        prng.random_bytes(reinterpret_cast<uint8_t*>(&a.limbs[0]), 8);
        a.limbs[0] = (a.limbs[0] % 1000000000ULL) + 2; 
        
        if (a >= n_minus_1) a = BigInt512(2);

        BigInt512 x = ExpMod(a, d, n); // Đảm bảo đã sửa ExpMod như hướng dẫn trước đó
        if (x == BigInt512(1) || x == n_minus_1) continue;

        bool composite = true;
        for (int j = 0; j < r - 1; ++j) {
            x = MultMod(x, x, n);      // Đảm bảo đã sửa MultMod như hướng dẫn trước đó
            if (x == n_minus_1) {
                composite = false;
                break;
            }
        }
        if (composite) return false;
    }
    return true;
}

// Tính nhanh (n mod m) với m là số nhỏ (< 2^31)
uint64_t mod_small(const BigInt512& n, uint64_t m) {
    uint64_t rem = 0;
    for (int i = BigInt512::NUM_LIMBS - 1; i >= 0; --i) {
        rem = ((rem << 32) | (n.limbs[i] >> 32)) % m;
        rem = ((rem << 32) | (n.limbs[i] & 0xFFFFFFFFULL)) % m;
    }
    return rem;
}

// Lọc nhanh các ứng viên q hoặc p = 2q + 1 chia hết cho số nguyên tố nhỏ
bool passes_small_primes(const BigInt512& q) {
    static const uint64_t small_primes[] = {
        3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73,
        79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157,
        163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239,
        241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331,
        337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421,
        431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509
    };
    for (uint64_t r : small_primes) {
        uint64_t rem_q = mod_small(q, r);
        if (rem_q == 0) return false;               // q là hợp số
        if ((2 * rem_q + 1) % r == 0) return false; // p = 2q + 1 là hợp số
    }
    return true;
}

// Sinh số nguyên tố an toàn p = 2q + 1
BigInt512 generate_safe_prime(PRNG& prng, int bit_size = 512) {
    std::cout << "Dang sinh so nguyen to an toan (" << bit_size << "-bit)...\n";
    while (true) {
        BigInt512 q = generate_random_512(prng, bit_size - 1);
        if (!passes_small_primes(q)) continue;

        if (miller_rabin(q, prng, 1)) {
            BigInt512 p = add(add(q, q), BigInt512(1));
            if (miller_rabin(p, prng, 1)) {
                // Xác minh kỹ thêm 4 vòng khi cả q và p đã vượt qua vòng 1
                if (miller_rabin(q, prng, 4) && miller_rabin(p, prng, 4)) {
                    return p;
                }
            }
        }
    }
}

BigInt512 generate_private_key(BigInt512 p, PRNG& prng) {
    BigInt512 key;
    prng.random_bytes(reinterpret_cast<uint8_t*>(key.limbs), 64);
    BigInt512 p_minus_3 = subtract(p, BigInt512(3));
    BigInt512 res = MOD(key, p_minus_3); // Sửa từ AddMod thành MOD
    return add(res, BigInt512(2));
}

BigInt512 generate_generator(BigInt512 p, PRNG& prng) {
    BigInt512 one(1);
    BigInt512 two(2);
    BigInt512 p_minus_1 = subtract(p, one);
    BigInt512 p_minus_3 = subtract(p, BigInt512(3));
    BigInt512 q = shift_right_1(p_minus_1); // q = (p - 1) / 2

    while (true) {
        // Sinh ngẫu nhiên ứng viên g trong khoảng [2, p - 2]
        BigInt512 rand_val;
        prng.random_bytes(reinterpret_cast<uint8_t*>(rand_val.limbs), 64);
        BigInt512 g = add(MOD(rand_val, p_minus_3), two);

        // Loại bỏ g = 2 để chọn giá trị khác theo yêu cầu đề bài
        if (g <= two) continue;

        // Kiểm tra điều kiện căn nguyên thủy: g^2 mod p != 1 và g^q mod p != 1
        if (modular_exponentiation(g, two, p) != one &&
            modular_exponentiation(g, q, p) != one) {
            return g;
        }
    }
}

// ============================================================================
// CHƯƠNG TRÌNH CHÍNH (TRAO ĐỔI KHÓA DIFFIE-HELLMAN)
// ============================================================================

int main() {
    std::cout << "==================================================\n";
    std::cout << " LAB 01: SO NGUYEN TO & TRAO DOI KHOA DIFFIE-HELLMAN\n";
    std::cout << "==================================================\n\n";

    // 0. Khởi tạo PRNG
    PRNG prng;
    std::random_device rd;
    uint8_t seed_data[32]; // Dùng 32 byte entropy
    for(int i = 0; i < 32; ++i) {
        seed_data[i] = static_cast<uint8_t>(rd());
    }
    prng.seed(seed_data, sizeof(seed_data));

    // 1. Sinh số nguyên tố an toàn p và phần tử sinh g
    int bit_size = 512; 
    BigInt512 p = generate_safe_prime(prng, bit_size);
    BigInt512 g = generate_generator(p, prng);

    std::cout << "[+] So nguyen to an toan p: "; p.print_hex(); std::cout << "\n";
    std::cout << "[+] Phan tu sinh g:         "; g.print_hex(); std::cout << "\n\n";

    // 2. Sinh khóa riêng của Alice và Bob
    BigInt512 a = generate_private_key(p, prng);
    BigInt512 b = generate_private_key(p, prng);

    std::cout << "[+] Khoa rieng Alice (a):   "; a.print_hex(); std::cout << "\n";
    std::cout << "[+] Khoa rieng Bob (b):     "; b.print_hex(); std::cout << "\n\n";

    // 3. Tính giá trị công khai (A = g^a mod p, B = g^b mod p)
    BigInt512 A = modular_exponentiation(g, a, p);
    BigInt512 B = modular_exponentiation(g, b, p);

    std::cout << "[+] Khoa cong khai Alice (A = g^a mod p): "; A.print_hex(); std::cout << "\n";
    std::cout << "[+] Khoa cong khai Bob   (B = g^b mod p): "; B.print_hex(); std::cout << "\n\n";

    // 4. Tính bí mật chung
    BigInt512 alice_shared_secret = modular_exponentiation(B, a, p);
    BigInt512 bob_shared_secret   = modular_exponentiation(A, b, p);

    std::cout << "[+] Bi mat chung Alice nhan duoc: "; alice_shared_secret.print_hex(); std::cout << "\n";
    std::cout << "[+] Bi mat chung Bob nhan duoc:   "; bob_shared_secret.print_hex(); std::cout << "\n\n";

    // 5. Xác minh bí mật chung trùng khớp
    std::cout << "[=>] Qua trinh tinh toan dung khong? "
              << (alice_shared_secret == bob_shared_secret ? "DUNG (TRUE)" : "SAI (FALSE)") << "\n";

    return 0;
}