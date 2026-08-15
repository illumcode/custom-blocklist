from pathlib import Path

# Папка, где лежат файлы
folder = Path(".")

# Какие файлы обрабатывать
extensions = {".txt", ".lst", ".csv", ".log"}

for file in folder.rglob("*"):
    if file.is_file() and file.suffix.lower() in extensions:
        try:
            text = file.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            text = file.read_text(encoding="cp1251")

        # Удаляем пустые строки
        lines = [line for line in text.splitlines() if line.strip()]

        file.write_text("\n".join(lines) + "\n", encoding="utf-8")

        print(f"Готово: {file}")

print("\nВсе пустые строки удалены.")
