import logging
import os

os.environ["KIVY_NO_CONFIG"] = "1"
os.environ["KIVY_NO_FILELOG"] = "1"
os.environ["KIVY_NO_CONSOLELOG"] = "1"
os.environ["KIVY_LOG_MODE"] = "PYTHON"
os.environ["KCFG_KIVY_LOG_ENABLE"] = "0"
os.environ["KCFG_KIVY_LOG_LEVEL"] = "critical"
logging.disable(logging.CRITICAL)

from kivy.app import App
from kivy.clock import Clock
from kivy.lang import Builder
from kivy.properties import StringProperty
from kivy.uix.boxlayout import BoxLayout

from netutil import local_addresses
from p2p import P2PNode


class RootView(BoxLayout):
    status_text = StringProperty("Hazir")
    security_text = StringProperty("-")
    invite_text = StringProperty("")

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.node = P2PNode(
            on_status=lambda value: Clock.schedule_once(lambda dt: self._set_status(value), 0),
            on_message=lambda value: Clock.schedule_once(lambda dt: self._add_message("Karsi taraf", value), 0),
            on_invite=lambda value: Clock.schedule_once(lambda dt: self._set_invite(value), 0),
            on_security=lambda value: Clock.schedule_once(lambda dt: self._set_security(value), 0),
        )
        Clock.schedule_once(lambda dt: self.detect_address(), 0)

    def detect_address(self):
        addresses = local_addresses()
        if addresses:
            self.ids.address_input.text = addresses[0]
            self.status_text = "Adres bulundu"
        else:
            self.status_text = "IP adresini elle girin"

    def host(self):
        address = self.ids.address_input.text.strip()
        self.ids.chat_label.text = ""
        port_text = self.ids.port_input.text.strip() or "0"
        try:
            port = int(port_text)
            self.invite_text = ""
            self.security_text = "-"
            self.node.start_host(address, port)
        except Exception:
            self.status_text = "Adres veya port gecersiz"

    def join(self):
        code = self.ids.join_input.text.strip()
        if not code:
            self.status_text = "Davet kodu girin"
            return
        self.security_text = "-"
        self.ids.chat_label.text = ""
        self.ids.join_input.text = ""
        self.node.connect(code)

    def send(self):
        text = self.ids.message_input.text
        if self.node.send_text(text):
            self._add_message("Sen", text)
            self.ids.message_input.text = ""
        else:
            self.status_text = "Mesaj gonderilemedi"

    def stop(self):
        self.node.disconnect()
        self.status_text = "Baglanti kapatildi"
        self.security_text = "-"
        self.invite_text = ""
        self.ids.join_input.text = ""
        self.ids.message_input.text = ""
        self.ids.chat_label.text = ""

    def _set_status(self, value):
        self.status_text = value
        if value == "Baglandi":
            self.invite_text = ""
            self.ids.join_input.text = ""

    def _set_invite(self, value):
        self.invite_text = value

    def _set_security(self, value):
        self.security_text = value

    def _add_message(self, sender, text):
        label = self.ids.chat_label
        line = f"{sender}: {text}"
        label.text = line if not label.text else label.text + "\n\n" + line
        Clock.schedule_once(lambda dt: setattr(self.ids.chat_scroll, "scroll_y", 0), 0)


class BlackTextApp(App):
    def build(self):
        self.title = "BlackText P2P"
        Builder.load_file("blacktext.kv")
        return RootView()

    def on_start(self):
        try:
            from android.runnable import run_on_ui_thread
            from jnius import autoclass

            @run_on_ui_thread
            def secure_window():
                activity = autoclass("org.kivy.android.PythonActivity").mActivity
                params = autoclass("android.view.WindowManager$LayoutParams")
                activity.getWindow().setFlags(params.FLAG_SECURE, params.FLAG_SECURE)

            secure_window()
        except Exception:
            pass

    def on_stop(self):
        if self.root is not None:
            self.root.node.disconnect()


if __name__ == "__main__":
    BlackTextApp().run()
