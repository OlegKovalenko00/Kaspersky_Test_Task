# Kaspersky Test Task — файловый сканер

Программа на **C++17**, которая рекурсивно обходит директорию, считает **MD5-хэши** файлов (через OpenSSL) и сверяет их с базой «плохих» хэшей. При совпадении результат записывается в `report.log`. Используется многопоточность (очередь + пул потоков).

---

## Сборка

```bash
git clone https://github.com/OlegKovalenko00/Kaspersky_Test_Task.git
cd Kaspersky_Test_Task

mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
cmake --build . -- -j$(nproc)
```

Если OpenSSL не установлен:
```bash
sudo apt install libssl-dev
```
или соберите через FetchContent:
```bash
cmake .. -DUSE_SYSTEM_OPENSSL=OFF -DOPENSSL_FETCH_IF_MISSING=ON
```

---

## Запуск

```bash
./scanner --base bad_hash.csv --log report.log --path /путь/к/директории
```

Опции:
- `--base <file>` — CSV с плохими хэшами (по умолчанию `bad_hash.csv`).
- `--log <file>` — лог (по умолчанию `report.log`).
- `--path <dir>` — директория для сканирования.
- `--help` — показать справку.

---

## Формат файлов

**bad_hash.csv**  
```
<md5_hex>;<описание>
```

**report.log** (при совпадении):  
```
<md5_hex>;<путь_к_файлу>;<описание>
```

---

## Пример работы

```bash
./scanner --base bad_hash.csv --log report.log --path ./testdir
```

Вывод:
```
5d41402abc4b2a76b9719d911017c592  ./testdir/hello.txt
Test virus sample Find
```
