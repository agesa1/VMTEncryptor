#include <iostream>
#include <vector>
#include <cstdint>
#include <cstring>
#include <random>
#include <Windows.h>

class AdvancedXorCipher {
private:
    std::vector<uint8_t> key;
    uint64_t seed;

    void generateDynamicKey(size_t length) {
        std::mt19937_64 rng(seed);
        key.resize(length);
        for (size_t i = 0; i < length; ++i) {
            key[i] = static_cast<uint8_t>(rng() % 256);
        }
    }

    uint8_t multiLayerXor(uint8_t byte, size_t position) {
        uint8_t result = byte;
        result ^= key[position % key.size()];
        result ^= static_cast<uint8_t>((position * 0x5D) & 0xFF);
        result ^= static_cast<uint8_t>((seed >> (position % 8)) & 0xFF);
        result = rotateLeft(result, position % 8);
        return result;
    }

    uint8_t rotateLeft(uint8_t value, int shift) {
        shift %= 8;
        return (value << shift) | (value >> (8 - shift));
    }

    uint8_t rotateRight(uint8_t value, int shift) {
        shift %= 8;
        return (value >> shift) | (value << (8 - shift));
    }

public:
    AdvancedXorCipher(uint64_t customSeed = 0) {
        if (customSeed == 0) {
            std::random_device rd;
            seed = (static_cast<uint64_t>(rd()) << 32) | rd();
        }
        else {
            seed = customSeed;
        }
        generateDynamicKey(256);
    }

    void encrypt(void* data, size_t size) {
        uint8_t* bytes = static_cast<uint8_t*>(data);
        for (size_t i = 0; i < size; ++i) {
            bytes[i] = multiLayerXor(bytes[i], i);
        }
    }

    void decrypt(void* data, size_t size) {
        uint8_t* bytes = static_cast<uint8_t*>(data);
        for (size_t i = 0; i < size; ++i) {
            bytes[i] = rotateRight(bytes[i], i % 8);
            bytes[i] ^= static_cast<uint8_t>((seed >> (i % 8)) & 0xFF);
            bytes[i] ^= static_cast<uint8_t>((i * 0x5D) & 0xFF);
            bytes[i] ^= key[i % key.size()];
        }
    }

    uint64_t getSeed() const { return seed; }
};

template<typename T>
class ProtectedVMT {
private:
    void** originalVTable;
    void** encryptedVTable;
    size_t vtableSize;
    AdvancedXorCipher cipher;
    bool isEncrypted;

    size_t calculateVTableSize(void** vtable) {
        size_t size = 0;
        MEMORY_BASIC_INFORMATION mbi;

        while (VirtualQuery(vtable[size], &mbi, sizeof(mbi)) &&
            mbi.State == MEM_COMMIT &&
            mbi.Protect != PAGE_NOACCESS) {
            if (vtable[size] == nullptr) break;
            size++;
            if (size > 100) break;
        }
        return size;
    }

    bool changeMemoryProtection(void* address, size_t size, DWORD newProtect, DWORD& oldProtect) {
        return VirtualProtect(address, size, newProtect, &oldProtect) != 0;
    }

public:
    ProtectedVMT(T* object, uint64_t seed = 0) : cipher(seed), isEncrypted(false) {
        originalVTable = *reinterpret_cast<void***>(object);
        vtableSize = calculateVTableSize(originalVTable);
        encryptedVTable = new void* [vtableSize];
    }

    ~ProtectedVMT() {
        if (encryptedVTable) {
            delete[] encryptedVTable;
        }
    }

    bool encryptVTable(T* object) {
        if (isEncrypted) {
            return false;
        }

        std::memcpy(encryptedVTable, originalVTable, vtableSize * sizeof(void*));
        cipher.encrypt(encryptedVTable, vtableSize * sizeof(void*));

        DWORD oldProtect;
        void*** objectVTablePtr = reinterpret_cast<void***>(object);

        if (!changeMemoryProtection(objectVTablePtr, sizeof(void**), PAGE_READWRITE, oldProtect)) {
            return false;
        }

        *objectVTablePtr = encryptedVTable;
        changeMemoryProtection(objectVTablePtr, sizeof(void**), oldProtect, oldProtect);

        isEncrypted = true;
        return true;
    }

    template<typename Ret, typename... Args>
    Ret callEncryptedMethod(T* object, size_t methodIndex, Args... args) {
        if (!isEncrypted) {
            return Ret();
        }

        void* tempVTable[256];
        std::memcpy(tempVTable, encryptedVTable, vtableSize * sizeof(void*));
        cipher.decrypt(tempVTable, vtableSize * sizeof(void*));

        using FuncPtr = Ret(*)(T*, Args...);
        FuncPtr func = reinterpret_cast<FuncPtr>(tempVTable[methodIndex]);
        Ret result = func(object, args...);

        std::memset(tempVTable, 0, vtableSize * sizeof(void*));
        return result;
    }

    bool decryptVTable(T* object) {
        if (!isEncrypted) {
            return false;
        }

        cipher.decrypt(encryptedVTable, vtableSize * sizeof(void*));

        DWORD oldProtect;
        void*** objectVTablePtr = reinterpret_cast<void***>(object);

        if (!changeMemoryProtection(objectVTablePtr, sizeof(void**), PAGE_READWRITE, oldProtect)) {
            return false;
        }

        *objectVTablePtr = originalVTable;
        changeMemoryProtection(objectVTablePtr, sizeof(void**), oldProtect, oldProtect);

        isEncrypted = false;
        return true;
    }

    bool isVTableEncrypted() const { return isEncrypted; }
    size_t getVTableSize() const { return vtableSize; }
};

class Base {
public:
    virtual void method1() {
        std::cout << "Base::method1() called\n";
    }

    virtual int method2(int x) {
        std::cout << "Base::method2(" << x << ") called\n";
        return x * 2;
    }

    virtual void method3() {
        std::cout << "Base::method3() called\n";
    }

    virtual ~Base() = default;
};

class Derived : public Base {
public:
    void method1() override {
        std::cout << "Derived::method1() called\n";
    }

    int method2(int x) override {
        std::cout << "Derived::method2(" << x << ") called\n";
        return x * 3;
    }

    void method3() override {
        std::cout << "Derived::method3() called\n";
    }
};

int main() {
    Derived* obj = new Derived();

    obj->method1();
    int result = obj->method2(5);
    std::cout << "Result: " << result << "\n";
    obj->method3();

    ProtectedVMT<Derived> protectedVMT(obj);
    protectedVMT.encryptVTable(obj);
    protectedVMT.decryptVTable(obj);

    obj->method1();
    result = obj->method2(10);
    std::cout << "Result: " << result << "\n";

    delete obj;
    return 0;
}
