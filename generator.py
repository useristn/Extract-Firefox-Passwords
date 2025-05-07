import re
from itertools import product

def normalize_name(name):
    """
    Chuẩn hóa tên:
    - Chuyển về chữ thường.
    - Loại bỏ ký tự đặc biệt.
    - Tách thành danh sách các phần tên.
    """
    name = re.sub(r"[^\w\s]", "", name.lower())
    return name.strip().split()

def generate_date_formats(day, month, year):
    """
    Sinh các biến thể ngày sinh thường gặp:
    - Bao gồm định dạng đầy đủ (DDMMYYYY), rút gọn (YYMMDD), đảo thứ tự, v.v.
    """
    d = str(int(day))
    m = str(int(month))
    dd = str(day).zfill(2)
    mm = str(month).zfill(2)
    yyyy = str(year)
    yy = yyyy[2:]

    return list(set([
        dd + mm + yyyy, mm + dd + yyyy, yyyy + mm + dd, yyyy + dd + mm,
        mm + yyyy, dd + yyyy, yyyy + mm, yyyy + dd,
        d + m + yyyy, m + d + yyyy, yyyy + m + d, yyyy + d + m,
        d + yyyy + m, m + yyyy + d, d + m + yy, dd + mm + yy,
        mm + dd + yy, yy + mm + dd
    ]))

def leet_variants(word):
    """
    Sinh các biến thể leetspeak (l33t) cho một từ:
    - Thay thế các ký tự: a → 4, e → 3, i → 1, o → 0, s → 5.
    - Tạo tất cả tổ hợp khả thi.
    """
    replacements = {
        "a": ["a", "4"],
        "e": ["e", "3"],
        "i": ["i", "1"],
        "o": ["o", "0"],
        "s": ["s", "5"]
    }

    def recursive_leet(w, index=0):
        if index == len(w):
            return [""]
        char = w[index]
        subs = replacements.get(char, [char])
        suffixes = recursive_leet(w, index + 1)
        return [s + suf for s in subs for suf in suffixes]

    return list(set(recursive_leet(word)))

def generate_wordlist(name, birthdate, filename="./Wordlists/custom_passwords.txt", keywords=None, enable_leet=True):
    """
    Tạo wordlist từ họ tên, ngày sinh và từ khóa.
    - Kết hợp các biến thể tên với ngày sinh, từ khóa và leetspeak.
    - Xuất ra file text.
    """
    try:
        name_parts = normalize_name(name) if name else []
        date_parts = []

        # Phân tích ngày sinh
        if birthdate:
            try:
                day, month, year = map(int, birthdate.strip().split("/"))
                date_parts = generate_date_formats(day, month, year)
                dd = str(day).zfill(2)
                mm = str(month).zfill(2)
                yy = str(year)[2:]
                yyyy = str(year)

            except ValueError:
                print("Invalid birthdate format. Using only name and keywords.")

        if keywords is None:
            keywords = ["123", "123456", "admin", "password", "secret", "qwerty", "abc", "xyz", "iloveyou", "love", "cute", "pro"]

        name_combos = set()

        if len(name_parts) == 3:
            f, m, l = name_parts
            name_combos.update([
                f, m, l,
                f + l, f + m, m + l,
                f + m + l, m + f + l, l + f + m,
                l + m + f, f + m + l + f,
                f + l + f, f + f + l
            ])
        elif len(name_parts) == 2:
            f, l = name_parts
            name_combos.update([f, l, f + l, l + f, f + f + l, f + l + f])
        elif name_parts:
            name_combos.update(name_parts)

        all_lines = set()

        # Tổ hợp tên + ngày sinh
        if name_combos and date_parts:
            for name, date in product(name_combos, date_parts):
                variations = [
                    name + date,
                    date + name,
                    name + "@" + date,
                    name + "_" + date,
                    name.capitalize() + date
                ]
                variations += [
                name + yy,
                name + dd + mm
                ]
                if enable_leet:
                    variations.extend(leet_variants(name + date))
                all_lines.update(variations)

                # Thêm keyword vào sau tên hoặc ngày sinh
                for kw in keywords:
                    all_lines.update([
                        name + kw,
                        kw + name,
                        name + date + kw,
                        kw + name + date,
                        name + "_" + kw,
                        name + "@" + kw
                    ])

            # Nếu không có ngày sinh, chỉ tạo tổ hợp tên và từ khóa
            if name_combos and birthdate:
                for name in name_combos:
                    all_lines.update([
                        name + yyyy,
                        name + dd + mm
                    ])
            else:
                for name in name_combos:
                    all_lines.update([
                        name,
                        name.capitalize()
                    ])

        # Tổ hợp chỉ tên
        for name in name_combos:
            all_lines.update([
                name,
                name.capitalize()
            ])
            for kw in keywords:
                all_lines.update([
                    name + kw,
                    kw + name,
                    name + "_" + kw,
                    name + "@" + kw
                ])
            if enable_leet:
                all_lines.update(leet_variants(name))

        # Chỉ ngày sinh
        all_lines.update(date_parts)

        # Nếu không có gì để ghi
        if not all_lines:
            print("No data to write. Please enter name or birthdate.")
            return

        # Ghi ra file
        with open(filename, "w", encoding="utf-8") as f:
            for line in sorted(all_lines):
                f.write(line + "\n")

        print(f"Wordlist generated in '{filename}' with {len(all_lines)} entries.")

    except Exception as e:
        print(f"An error occurred: {e}")

def main():
    try:
        full_name = input("Enter full name: ").strip()
        birthdate = input("Enter birthdate (DD/MM/YYYY): ").strip()

        if not full_name and not birthdate:
            print("At least one of name or birthdate must be provided.")
        else:
            generate_wordlist(full_name, birthdate)

    except KeyboardInterrupt:
        print("\nOperation canceled by user.")

if __name__ == "__main__":
    main()