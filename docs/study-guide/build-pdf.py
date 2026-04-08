#!/usr/bin/env python3
"""
Build the Cullis Study Guide PDF from all markdown chapters.
Uses fpdf2 (pure Python, no system deps).

Usage: python docs/study-guide/build-pdf.py
Output: docs/study-guide/cullis-study-guide.pdf
"""
import glob
import os
import re
import textwrap

from fpdf import FPDF

GUIDE_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_PDF = os.path.join(GUIDE_DIR, "cullis-study-guide.pdf")

chapter_files = sorted(glob.glob(os.path.join(GUIDE_DIR, "[0-3]*.md")))

PARTS = {
    1: ("I", "Fondamenti"),
    4: ("II", "Crittografia e PKI"),
    9: ("III", "Autenticazione e Token"),
    14: ("IV", "Messaging e Sessioni"),
    17: ("V", "Policy Engine"),
    20: ("VI", "Infrastruttura e Deploy"),
    27: ("VII", "Observability e Audit"),
    30: ("VIII", "SDK e Integrazioni"),
    34: ("IX", "Sicurezza Applicativa"),
    37: ("X", "Standard e RFC"),
}

# Colors
INDIGO = (79, 70, 229)
DARK = (30, 27, 75)
GRAY = (100, 116, 139)
LIGHT_BG = (245, 243, 255)
CODE_BG = (30, 41, 59)
CODE_FG = (226, 232, 240)
WHITE = (255, 255, 255)
TABLE_HEADER_BG = (79, 70, 229)
TABLE_ALT_BG = (249, 250, 251)
QUOTE_BORDER = (99, 102, 241)
QUOTE_BG = (245, 243, 255)


class StudyGuidePDF(FPDF):

    def __init__(self):
        super().__init__()
        self.set_auto_page_break(auto=True, margin=25)
        _F = "/nix/store/xbs17gmksi0pljxcs4l6gshklzpmv8gr-dejavu-fonts-2.37/share/fonts/truetype"
        self.add_font("DejaVu", "", f"{_F}/DejaVuSans.ttf", uni=True)
        self.add_font("DejaVu", "B", f"{_F}/DejaVuSans-Bold.ttf", uni=True)
        self.add_font("DejaVu", "I", f"{_F}/DejaVuSans-Oblique.ttf", uni=True)
        self.add_font("DejaVu", "BI", f"{_F}/DejaVuSans-BoldOblique.ttf", uni=True)
        self.add_font("DejaVuMono", "", f"{_F}/DejaVuSansMono.ttf", uni=True)
        self.add_font("DejaVuMono", "B", f"{_F}/DejaVuSansMono-Bold.ttf", uni=True)
        self.toc_entries = []
        self.current_chapter = ""

    def header(self):
        if self.page_no() <= 2:
            return
        self.set_font("DejaVu", "I", 8)
        self.set_text_color(*GRAY)
        title = self.current_chapter if self.current_chapter else "Cullis Study Guide"
        self.cell(0, 8, title, align="L")
        self.ln(3)
        self.set_draw_color(220, 220, 220)
        self.line(10, self.get_y(), 200, self.get_y())
        self.ln(5)

    def footer(self):
        if self.page_no() <= 1:
            return
        self.set_y(-15)
        self.set_font("DejaVu", "", 8)
        self.set_text_color(*GRAY)
        self.cell(0, 10, str(self.page_no()), align="C")

    def cover_page(self):
        self.add_page()
        # Background
        self.set_fill_color(30, 27, 75)
        self.rect(0, 0, 210, 297, "F")

        # Title
        self.set_y(80)
        self.set_font("DejaVu", "B", 48)
        self.set_text_color(*WHITE)
        self.cell(0, 20, "CULLIS", align="C", new_x="LMARGIN", new_y="NEXT")

        self.ln(5)
        self.set_font("DejaVu", "", 14)
        self.set_text_color(199, 210, 254)
        self.cell(0, 8, "Guida Completa allo Studio", align="C", new_x="LMARGIN", new_y="NEXT")
        self.ln(3)
        self.set_font("DejaVu", "I", 11)
        self.cell(0, 7, "Zero-Trust Identity e Authorization", align="C", new_x="LMARGIN", new_y="NEXT")
        self.cell(0, 7, "per AI Agent-to-Agent Communication", align="C", new_x="LMARGIN", new_y="NEXT")

        self.ln(15)
        self.set_draw_color(99, 102, 241)
        self.set_line_width(0.5)
        self.line(60, self.get_y(), 150, self.get_y())

        self.ln(15)
        self.set_font("DejaVu", "", 10)
        self.set_text_color(167, 176, 210)
        self.cell(0, 7, "37 capitoli  \u2022  ~250 pagine  \u2022  Aprile 2026", align="C", new_x="LMARGIN", new_y="NEXT")
        self.ln(5)
        self.set_font("DejaVu", "I", 9)
        self.cell(0, 6, "Dalla teoria alla pratica \u2014 ogni concetto spiegato semplice,", align="C", new_x="LMARGIN", new_y="NEXT")
        self.cell(0, 6, "ogni tecnologia collegata al codice reale del progetto.", align="C", new_x="LMARGIN", new_y="NEXT")

    def toc_page(self):
        self.add_page()
        self.set_font("DejaVu", "B", 22)
        self.set_text_color(*INDIGO)
        self.cell(0, 15, "Indice", new_x="LMARGIN", new_y="NEXT")
        self.set_draw_color(*INDIGO)
        self.set_line_width(0.8)
        self.line(10, self.get_y(), 80, self.get_y())
        self.ln(8)

        # We'll fill this in after all pages are rendered
        # For now just reserve the page

    def part_page(self, part_num, part_title):
        self.add_page()
        self.set_fill_color(*LIGHT_BG)
        self.rect(0, 0, 210, 297, "F")

        self.set_y(100)
        self.set_font("DejaVu", "", 16)
        self.set_text_color(*INDIGO)
        self.cell(0, 12, f"Parte {part_num}", align="C", new_x="LMARGIN", new_y="NEXT")

        self.set_font("DejaVu", "B", 28)
        self.set_text_color(*DARK)
        self.cell(0, 16, part_title, align="C", new_x="LMARGIN", new_y="NEXT")

        self.ln(10)
        self.set_draw_color(*INDIGO)
        self.set_line_width(0.5)
        self.line(70, self.get_y(), 140, self.get_y())

    def render_markdown(self, md_text, chapter_num):
        lines = md_text.split("\n")
        in_code_block = False
        code_lines = []
        in_table = False
        table_rows = []

        i = 0
        while i < len(lines):
            line = lines[i]

            # Code block toggle
            if line.strip().startswith("```"):
                if in_code_block:
                    self._render_code_block(code_lines)
                    code_lines = []
                    in_code_block = False
                else:
                    if in_table:
                        self._render_table(table_rows)
                        table_rows = []
                        in_table = False
                    in_code_block = True
                i += 1
                continue

            if in_code_block:
                code_lines.append(line)
                i += 1
                continue

            # Table
            if "|" in line and line.strip().startswith("|"):
                cells = [c.strip() for c in line.strip().strip("|").split("|")]
                # Skip separator rows
                if all(re.match(r'^[-:]+$', c) for c in cells):
                    i += 1
                    continue
                table_rows.append(cells)
                in_table = True
                i += 1
                continue
            elif in_table:
                self._render_table(table_rows)
                table_rows = []
                in_table = False

            stripped = line.strip()

            # Empty line
            if not stripped:
                self.ln(3)
                i += 1
                continue

            # Horizontal rule
            if stripped in ("---", "***", "___"):
                self.ln(3)
                self.set_draw_color(220, 220, 220)
                self.set_line_width(0.3)
                self.line(10, self.get_y(), 200, self.get_y())
                self.ln(5)
                i += 1
                continue

            # H1
            if stripped.startswith("# "):
                title = stripped[2:].strip()
                if chapter_num > 0:
                    self.current_chapter = title
                    self.toc_entries.append((title, self.page_no(), 1))
                self.ln(5)
                self.set_font("DejaVu", "B", 18)
                self.set_text_color(*DARK)
                self.multi_cell(0, 9, title)
                self.set_draw_color(*INDIGO)
                self.set_line_width(0.5)
                self.line(10, self.get_y() + 1, 200, self.get_y() + 1)
                self.ln(6)
                i += 1
                continue

            # H2
            if stripped.startswith("## "):
                title = stripped[3:].strip()
                self.toc_entries.append((title, self.page_no(), 2))
                self.ln(4)
                self.set_font("DejaVu", "B", 14)
                self.set_text_color(49, 46, 129)
                self.multi_cell(0, 8, title)
                self.set_draw_color(229, 231, 235)
                self.set_line_width(0.2)
                self.line(10, self.get_y() + 1, 200, self.get_y() + 1)
                self.ln(4)
                i += 1
                continue

            # H3
            if stripped.startswith("### "):
                title = stripped[4:].strip()
                self.ln(3)
                self.set_font("DejaVu", "B", 12)
                self.set_text_color(67, 56, 202)
                self.multi_cell(0, 7, title)
                self.ln(3)
                i += 1
                continue

            # H4
            if stripped.startswith("#### "):
                title = stripped[5:].strip()
                self.ln(2)
                self.set_font("DejaVu", "B", 10.5)
                self.set_text_color(99, 102, 241)
                self.multi_cell(0, 6, title)
                self.ln(2)
                i += 1
                continue

            # Blockquote
            if stripped.startswith("> "):
                quote_text = stripped[2:]
                # Collect multi-line quotes
                while i + 1 < len(lines) and lines[i + 1].strip().startswith("> "):
                    i += 1
                    quote_text += " " + lines[i].strip()[2:]

                self.ln(2)
                x = self.get_x()
                y = self.get_y()
                self.set_fill_color(*QUOTE_BG)
                self.set_font("DejaVu", "I", 10)
                self.set_text_color(67, 56, 202)
                # Calculate height
                self.set_x(18)
                self.multi_cell(175, 6, self._clean_md(quote_text), fill=True)
                end_y = self.get_y()
                # Draw left border
                self.set_draw_color(*QUOTE_BORDER)
                self.set_line_width(1)
                self.line(13, y, 13, end_y + 2)
                self.ln(4)
                i += 1
                continue

            # List items
            if stripped.startswith("- ") or stripped.startswith("* "):
                text = stripped[2:]
                self.set_font("DejaVu", "", 10)
                self.set_text_color(26, 26, 26)
                self.set_x(15)
                self.cell(5, 6, "\u2022")
                self.set_x(20)
                self.multi_cell(170, 6, self._clean_md(text))
                self.ln(1)
                i += 1
                continue

            # Numbered list
            m = re.match(r'^(\d+)\.\s+(.*)', stripped)
            if m:
                num, text = m.group(1), m.group(2)
                self.set_font("DejaVu", "", 10)
                self.set_text_color(26, 26, 26)
                self.set_x(15)
                self.cell(8, 6, f"{num}.")
                self.set_x(23)
                self.multi_cell(167, 6, self._clean_md(text))
                self.ln(1)
                i += 1
                continue

            # Regular paragraph
            self.set_font("DejaVu", "", 10)
            self.set_text_color(26, 26, 26)
            self.multi_cell(0, 6, self._clean_md(stripped))
            self.ln(2)
            i += 1

        # Flush remaining
        if in_code_block and code_lines:
            self._render_code_block(code_lines)
        if in_table and table_rows:
            self._render_table(table_rows)

    def _clean_md(self, text):
        """Strip markdown formatting for plain text output."""
        text = re.sub(r'\*\*(.+?)\*\*', r'\1', text)
        text = re.sub(r'\*(.+?)\*', r'\1', text)
        text = re.sub(r'`(.+?)`', r'\1', text)
        text = re.sub(r'\[(.+?)\]\(.+?\)', r'\1', text)
        text = text.replace("&mdash;", "\u2014")
        text = text.replace("&bull;", "\u2022")
        text = text.replace("&rarr;", "\u2192")
        text = text.replace("→", "\u2192")
        text = text.replace("←", "\u2190")
        text = text.replace("✓", "\u2713")
        text = text.replace("✗", "\u2717")
        text = text.replace("★", "\u2605")
        return text

    def _render_code_block(self, lines):
        self.ln(2)
        x_start = 12
        width = 186
        self.set_font("DejaVuMono", "", 7.5)

        # Calculate total height
        line_h = 4.5
        padding = 4
        total_h = len(lines) * line_h + padding * 2

        # Check page break
        if self.get_y() + total_h > 270:
            self.add_page()

        y_start = self.get_y()
        self.set_fill_color(*CODE_BG)
        self.rect(x_start, y_start, width, total_h, "F")

        self.set_text_color(*CODE_FG)
        self.set_y(y_start + padding)
        for line in lines:
            self.set_x(x_start + 4)
            # Truncate very long lines
            if len(line) > 105:
                line = line[:102] + "..."
            self.cell(width - 8, line_h, line)
            self.ln(line_h)

        self.set_y(y_start + total_h + 2)
        self.ln(2)

    def _render_table(self, rows):
        if not rows:
            return
        self.ln(2)
        n_cols = max(len(r) for r in rows)
        col_w = 186 / n_cols

        # Check page break (rough estimate)
        if self.get_y() + len(rows) * 8 > 270:
            self.add_page()

        for row_idx, row in enumerate(rows):
            # Pad row to n_cols
            while len(row) < n_cols:
                row.append("")

            if row_idx == 0:
                self.set_fill_color(*TABLE_HEADER_BG)
                self.set_text_color(*WHITE)
                self.set_font("DejaVu", "B", 8.5)
            else:
                if row_idx % 2 == 0:
                    self.set_fill_color(*TABLE_ALT_BG)
                else:
                    self.set_fill_color(*WHITE)
                self.set_text_color(26, 26, 26)
                self.set_font("DejaVu", "", 8.5)

            self.set_x(12)
            for cell in row:
                text = self._clean_md(cell)
                if len(text) > 40:
                    text = text[:37] + "..."
                self.cell(col_w, 7, text, border=0, fill=True)
            self.ln(7)

        self.ln(3)


def main():
    print("Building Cullis Study Guide PDF...")
    print(f"  Chapters: {len(chapter_files)}")

    pdf = StudyGuidePDF()
    pdf.set_title("Cullis - Guida Completa allo Studio")
    pdf.set_author("Cullis Project")

    # Cover
    pdf.cover_page()

    # Process chapters
    for fpath in chapter_files:
        fname = os.path.basename(fpath)
        # Extract chapter number
        m = re.match(r"(\d+)", fname)
        chapter_num = int(m.group(1)) if m else -1

        # Part divider
        if chapter_num in PARTS:
            part_num, part_title = PARTS[chapter_num]
            pdf.part_page(part_num, part_title)

        # Chapter content — always start on a new page
        pdf.add_page()

        with open(fpath, "r") as f:
            content = f.read()

        pdf.render_markdown(content, chapter_num)

    pdf.output(OUTPUT_PDF)
    size_mb = os.path.getsize(OUTPUT_PDF) / (1024 * 1024)
    print(f"  PDF: {OUTPUT_PDF} ({size_mb:.1f} MB)")
    print(f"  Pages: {pdf.page_no()}")
    print("Done!")


if __name__ == "__main__":
    main()
