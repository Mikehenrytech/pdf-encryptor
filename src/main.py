import os
import sys
import json
import inspect
from pathlib import Path
from typing import Dict, Optional

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QApplication,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QFileDialog,
    QMessageBox,
    QGroupBox,
    QFormLayout,
)

from pypdf import PdfReader, PdfWriter

VERSION: str = "1.0.3"


# ---------------------------
# PyInstaller-safe resource path
# ---------------------------
def resource_base_dir() -> Path:
    """
    Project layout:
      project/
        src/main.py
        i18n/en.json
        i18n/es.json

    - Dev: project/
    - PyInstaller onefile: sys._MEIPASS
    """
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        return Path(sys._MEIPASS)
    # __file__ = project/src/main.py → parent = src → parent.parent = project
    return Path(__file__).resolve().parent.parent


# ---------------------------
# Crypto helpers
# ---------------------------
def encrypt_writer_compat(writer: PdfWriter, user_password: str, owner_password: Optional[str]) -> None:
    if not owner_password:
        owner_password = user_password

    sig = inspect.signature(writer.encrypt)
    params = sig.parameters

    kwargs: dict = {}

    if "user_password" in params:
        kwargs["user_password"] = user_password
        kwargs["owner_password"] = owner_password
    elif "user_pwd" in params:
        kwargs["user_pwd"] = user_password
        kwargs["owner_pwd"] = owner_password

    if "algorithm" in params:
        kwargs["algorithm"] = "AES-256"
    elif "encryption_algorithm" in params:
        kwargs["encryption_algorithm"] = "AES-256"

    try:
        if kwargs:
            writer.encrypt(**kwargs)
            return
    except TypeError:
        pass

    try:
        writer.encrypt(user_password, owner_password)  # type: ignore[arg-type]
    except Exception as e:
        raise RuntimeError(f"No se pudo aplicar cifrado con la firma actual de pypdf: {sig}") from e


def encrypt_pdf(input_path: str, output_path: str, user_password: str, owner_password: Optional[str] = None) -> None:
    reader = PdfReader(input_path)
    writer = PdfWriter()

    for page in reader.pages:
        writer.add_page(page)

    encrypt_writer_compat(writer, user_password=user_password, owner_password=owner_password)

    out_dir = os.path.dirname(output_path)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)

    with open(output_path, "wb") as f:
        writer.write(f)


# ---------------------------
# i18n via JSON files
# ---------------------------
class I18N:
    LANG_ES = "es"
    LANG_EN = "en"

    def __init__(self, lang: str = LANG_ES) -> None:
        self.lang = lang
        self.base_dir = resource_base_dir()
        self._cache: Dict[str, Dict[str, str]] = {}
        self._strings = self._load_lang(self.lang)

    def _lang_path(self, lang: str) -> Path:
        return self.base_dir / "i18n" / f"{lang}.json"

    def _load_lang(self, lang: str) -> Dict[str, str]:
        if lang in self._cache:
            return self._cache[lang]

        path = self._lang_path(lang)
        if not path.exists():
            raise FileNotFoundError(f"Missing i18n file: {path}")

        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)

        if not isinstance(data, dict):
            raise ValueError(f"Invalid i18n JSON structure in {path}")

        self._cache[lang] = {str(k): str(v) for k, v in data.items()}
        return self._cache[lang]

    def set_lang(self, lang: str) -> None:
        self.lang = lang
        self._strings = self._load_lang(lang)

    def toggle(self) -> None:
        self.set_lang(self.LANG_EN if self.lang == self.LANG_ES else self.LANG_ES)

    def t(self, key: str) -> str:
        if key in self._strings:
            return self._strings[key]
        try:
            return self._load_lang(self.LANG_EN).get(key, key)
        except Exception:
            return key


# ---------------------------
# UI
# ---------------------------
class PdfEncryptor(QWidget):
    def __init__(self) -> None:
        super().__init__()

        # Spanish by default
        self.i18n = I18N(lang=I18N.LANG_ES)

        self.input_path_edit = QLineEdit()
        self.input_path_edit.setReadOnly(True)

        self.output_path_edit = QLineEdit()
        self.output_path_edit.setReadOnly(True)

        self.pass_edit = QLineEdit()
        self.pass_edit.setEchoMode(QLineEdit.Password)

        self.pass_confirm_edit = QLineEdit()
        self.pass_confirm_edit.setEchoMode(QLineEdit.Password)

        self.owner_pass_edit = QLineEdit()
        self.owner_pass_edit.setEchoMode(QLineEdit.Password)

        self.btn_browse_in = QPushButton()
        self.btn_browse_out = QPushButton()
        self.btn_encrypt = QPushButton()
        self.btn_encrypt.setDefault(True)

        self.btn_lang = QPushButton()
        self.btn_lang.setToolTip("Toggle language / Cambiar idioma")

        self.status_label = QLabel("")
        self.status_label.setWordWrap(True)
        self.status_label.setTextInteractionFlags(Qt.TextSelectableByMouse)

        self.files_group = QGroupBox()
        self.pass_group = QGroupBox()

        self.lbl_input = QLabel()
        self.lbl_output = QLabel()
        self.lbl_pass = QLabel()
        self.lbl_confirm = QLabel()
        self.lbl_owner = QLabel()

        self._build_ui()
        self._wire_events()
        self.apply_i18n()


    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)

        top_row = QHBoxLayout()
        top_row.addStretch(1)
        top_row.addWidget(self.btn_lang)
        layout.addLayout(top_row)

        files_form = QFormLayout(self.files_group)

        in_row = QHBoxLayout()
        in_row.addWidget(self.input_path_edit, 1)
        in_row.addWidget(self.btn_browse_in)
        files_form.addRow(self.lbl_input, in_row)

        out_row = QHBoxLayout()
        out_row.addWidget(self.output_path_edit, 1)
        out_row.addWidget(self.btn_browse_out)
        files_form.addRow(self.lbl_output, out_row)

        pass_form = QFormLayout(self.pass_group)
        pass_form.addRow(self.lbl_pass, self.pass_edit)
        pass_form.addRow(self.lbl_confirm, self.pass_confirm_edit)
        pass_form.addRow(self.lbl_owner, self.owner_pass_edit)

        layout.addWidget(self.files_group)
        layout.addWidget(self.pass_group)
        layout.addWidget(self.btn_encrypt)
        layout.addWidget(self.status_label)

        self.setMinimumWidth(620)

    def _wire_events(self) -> None:
        self.btn_browse_in.clicked.connect(self.pick_input_pdf)
        self.btn_browse_out.clicked.connect(self.pick_output_pdf)
        self.btn_encrypt.clicked.connect(self.run_encrypt)
        self.btn_lang.clicked.connect(self.toggle_language)

    def apply_i18n(self) -> None:
        t = self.i18n.t

        self.setWindowTitle(f"{t('app_title')} v{VERSION}")
        self.files_group.setTitle(t("files_group"))
        self.pass_group.setTitle(t("passwords_group"))

        self.lbl_input.setText(t("input_pdf"))
        self.lbl_output.setText(t("output_pdf"))

        self.btn_browse_in.setText(t("btn_select_pdf"))
        self.btn_browse_out.setText(t("btn_choose_output"))
        self.btn_encrypt.setText(t("btn_encrypt"))

        self.lbl_pass.setText(t("password_open"))
        self.lbl_confirm.setText(t("password_confirm"))
        self.lbl_owner.setText(t("password_owner"))

        self.owner_pass_edit.setPlaceholderText(t("owner_placeholder"))

        # Show target language label on the button (UX)
        if self.i18n.lang == I18N.LANG_ES:
            self.btn_lang.setText(t("lang_button_to_en"))
        else:
            self.btn_lang.setText(t("lang_button_to_es"))

    def toggle_language(self) -> None:
        self.i18n.toggle()
        self.apply_i18n()

    def pick_input_pdf(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self,
            self.i18n.t("dlg_pick_input_title"),
            "",
            "PDF (*.pdf)"
        )
        if not path:
            return

        self.input_path_edit.setText(path)

        in_path = Path(path)
        suffix = "_protected" if self.i18n.lang == I18N.LANG_EN else "_protegido"
        suggested = in_path.with_name(in_path.stem + suffix + ".pdf")
        self.output_path_edit.setText(str(suggested))

    def pick_output_pdf(self) -> None:
        suggested = self.output_path_edit.text().strip() or ""
        path, _ = QFileDialog.getSaveFileName(
            self,
            self.i18n.t("dlg_pick_output_title"),
            suggested,
            "PDF (*.pdf)"
        )
        if not path:
            return

        if not path.lower().endswith(".pdf"):
            path += ".pdf"
        self.output_path_edit.setText(path)

    def _error(self, title: str, msg: str) -> None:
        QMessageBox.critical(self, title, msg)

    def _info(self, title: str, msg: str) -> None:
        QMessageBox.information(self, title, msg)

    def run_encrypt(self) -> None:
        t = self.i18n.t

        in_path = self.input_path_edit.text().strip()
        out_path = self.output_path_edit.text().strip()
        p1 = self.pass_edit.text()
        p2 = self.pass_confirm_edit.text()
        owner = self.owner_pass_edit.text().strip() or None

        if not in_path:
            return self._error(t("err_missing_pdf_title"), t("err_missing_pdf_msg"))
        if not os.path.isfile(in_path):
            return self._error(t("err_invalid_input_title"), t("err_invalid_input_msg_missing"))
        if not in_path.lower().endswith(".pdf"):
            return self._error(t("err_invalid_input_title"), t("err_invalid_input_msg_notpdf"))

        if not out_path:
            return self._error(t("err_missing_output_title"), t("err_missing_output_msg"))
        if os.path.abspath(in_path) == os.path.abspath(out_path):
            return self._error(t("err_invalid_output_title"), t("err_invalid_output_msg_same"))

        if not p1:
            return self._error(t("err_empty_pass_title"), t("err_empty_pass_msg"))
        if p1 != p2:
            return self._error(t("err_mismatch_title"), t("err_mismatch_msg"))

        if len(p1) < 10:
            r = QMessageBox.warning(
                self,
                t("warn_short_title"),
                t("warn_short_msg"),
                QMessageBox.Yes | QMessageBox.No,
            )
            if r != QMessageBox.Yes:
                return

        try:
            self.btn_encrypt.setEnabled(False)
            self.status_label.setText(t("status_processing"))
            QApplication.processEvents()

            encrypt_pdf(in_path, out_path, user_password=p1, owner_password=owner)

            self.status_label.setText(f"{t('status_ok')}\n{out_path}")
            self._info(t("info_done_title"), t("info_done_msg"))
        except Exception as e:
            self.status_label.setText("")
            self._error(t("err_encrypt_title"), t("err_encrypt_msg").format(error=e))
        finally:
            self.btn_encrypt.setEnabled(True)


def main() -> int:
    app = QApplication(sys.argv)
    w = PdfEncryptor()
    w.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
