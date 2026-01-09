def handle_b105(vuln_info: dict, file_contents: list[str]) -> list[str]:
    line_number = vuln_info.get("Line")
    if not line_number:
        return file_contents

    index = line_number - 1

    if index < 0 or index >= len(file_contents):
        return file_contents

    # Zachowaj wcięcie (indentację)
    original_line = file_contents[index]
    indentation = original_line[: len(original_line) - len(original_line.lstrip())]

    # Przykładowa bezpieczna podmiana
    remediated_line = (
        f'{indentation}password = os.getenv("PASSWORD")  # SET PASSWORD IN ENV VAR\n'
    )

    file_contents[index] = remediated_line
    return file_contents
