import os
import sys
import inspect
from pathlib import Path

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


def encrypt_writer_compat(writer: PdfWriter, user_password: str, owner_password: str | None) -> None:
    """
    Encrypt PdfWriter in a way that is compatible across pypdf versions.

    - Newer versions: encrypt(user_password=..., owner_password=..., algorithm="AES-256")
    - Older versions: encrypt(user_pwd=..., owner_pwd=..., encryption_algorithm="AES-256") or variations
    - Very old versions: no AES-256 selector available -> encrypt still works but algorithm may be weaker
    """
    if not owner_password:
        owner_password = user_password

    sig = inspect.signature(writer.encrypt)
    params = sig.parameters

    kwargs: dict = {}

    # Password argument names differ across versions
    if "user_password" in params:
        kwargs["user_password"] = user_password
        kwargs["owner_password"] = owner_password
    elif "user_pwd" in params:
        kwargs["user_pwd"] = user_password
        kwargs["owner_pwd"] = owner_password
    else:
        # Fallback: best effort for unknown signatures
        # Some versions accept positional args; try later if kwargs fails
        kwargs = {}

    # Algorithm selector differs across versions
    if "algorithm" in params:
        kwargs["algorithm"] = "AES-256"
    elif "encryption_algorithm" in params:
        kwargs["encryption_algorithm"] = "AES-256"

    # Try with kwargs first
    try:
        if kwargs:
            writer.encrypt(**kwargs)
            return
    except TypeError:
        pass

    # Fallback: positional call (best effort)
    try:
        # Most common legacy signature: encrypt(user_pwd, owner_pwd, use_128bit=False)
        # We aim for strongest available; use_128bit=False can map to stronger encryption in some forks.
        writer.encrypt(user_password, owner_password)  # type: ignore[arg-type]
    except Exception as e:
        raise RuntimeError(f"No se pudo aplicar cifrado con la firma actual de pypdf: {sig}") from e


def encrypt_pdf(input_path: str, output_path: str, user_password: str, owner_password: str | None = None) -> None:
    """
    Reads input PDF, writes encrypted output PDF (attempting AES-256 where supported).
    """
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


class PdfEncryptor(QWidget):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("PDF con contraseña (PySide6 + pypdf)")
        self.setMinimumWidth(620)

        # Inputs
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
        self.owner_pass_edit.setPlaceholderText("(Opcional) Si lo dejas vacío, se usa la contraseña de apertura")

        # Buttons
        self.btn_browse_in = QPushButton("Seleccionar PDF…")
        self.btn_browse_out = QPushButton("Elegir salida…")
        self.btn_encrypt = QPushButton("Crear PDF protegido")
        self.btn_encrypt.setDefault(True)

        # Status
        self.status_label = QLabel("")
        self.status_label.setWordWrap(True)
        self.status_label.setTextInteractionFlags(Qt.TextSelectableByMouse)

        self._build_ui()
        self._wire_events()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)

        files_group = QGroupBox("Archivos")
        files_form = QFormLayout(files_group)

        in_row = QHBoxLayout()
        in_row.addWidget(self.input_path_edit, 1)
        in_row.addWidget(self.btn_browse_in)
        files_form.addRow("PDF de entrada:", in_row)

        out_row = QHBoxLayout()
        out_row.addWidget(self.output_path_edit, 1)
        out_row.addWidget(self.btn_browse_out)
        files_form.addRow("PDF de salida:", out_row)

        pass_group = QGroupBox("Contraseñas")
        pass_form = QFormLayout(pass_group)
        pass_form.addRow("Contraseña (apertura):", self.pass_edit)
        pass_form.addRow("Confirmación:", self.pass_confirm_edit)
        pass_form.addRow("Contraseña owner:", self.owner_pass_edit)

        layout.addWidget(files_group)
        layout.addWidget(pass_group)
        layout.addWidget(self.btn_encrypt)
        layout.addWidget(self.status_label)

    def _wire_events(self) -> None:
        self.btn_browse_in.clicked.connect(self.pick_input_pdf)
        self.btn_browse_out.clicked.connect(self.pick_output_pdf)
        self.btn_encrypt.clicked.connect(self.run_encrypt)

    def pick_input_pdf(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Selecciona PDF de entrada", "", "PDF (*.pdf)")
        if not path:
            return

        self.input_path_edit.setText(path)

        # Suggest output
        in_path = Path(path)
        suggested = in_path.with_name(in_path.stem + "_protegido.pdf")
        self.output_path_edit.setText(str(suggested))

    def pick_output_pdf(self) -> None:
        suggested = self.output_path_edit.text().strip() or ""
        path, _ = QFileDialog.getSaveFileName(self, "Guardar PDF de salida", suggested, "PDF (*.pdf)")
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
        in_path = self.input_path_edit.text().strip()
        out_path = self.output_path_edit.text().strip()
        p1 = self.pass_edit.text()
        p2 = self.pass_confirm_edit.text()
        owner = self.owner_pass_edit.text().strip() or None

        # Validations
        if not in_path:
            return self._error("Falta el PDF", "Selecciona un PDF de entrada.")
        if not os.path.isfile(in_path):
            return self._error("Entrada inválida", "El archivo de entrada no existe.")
        if not in_path.lower().endswith(".pdf"):
            return self._error("Entrada inválida", "El archivo de entrada no parece un PDF.")

        if not out_path:
            return self._error("Falta salida", "Elige la ruta del PDF de salida.")
        if os.path.abspath(in_path) == os.path.abspath(out_path):
            return self._error("Salida inválida", "La salida no puede ser el mismo archivo que la entrada.")

        if not p1:
            return self._error("Contraseña vacía", "La contraseña no puede estar vacía.")
        if p1 != p2:
            return self._error("No coincide", "La contraseña y su confirmación no coinciden.")

        # Soft warning for short password
        if len(p1) < 10:
            r = QMessageBox.warning(
                self,
                "Contraseña corta",
                "La contraseña parece corta (< 10 caracteres). ¿Quieres continuar igualmente?",
                QMessageBox.Yes | QMessageBox.No,
            )
            if r != QMessageBox.Yes:
                return

        # Encrypt
        try:
            self.btn_encrypt.setEnabled(False)
            self.status_label.setText("Procesando…")
            QApplication.processEvents()

            encrypt_pdf(in_path, out_path, user_password=p1, owner_password=owner)

            self.status_label.setText(f"OK: generado\n{out_path}")
            self._info("Listo", "PDF protegido creado correctamente.")
        except Exception as e:
            self.status_label.setText("")
            self._error("Error al cifrar", f"No se pudo crear el PDF protegido.\n\nDetalle:\n{e}")
        finally:
            self.btn_encrypt.setEnabled(True)


def main() -> int:
    app = QApplication(sys.argv)
    w = PdfEncryptor()
    w.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
