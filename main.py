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

from p2p import P2PNode, local_addresses


KV = r'''
#:import dp kivy.metrics.dp

<RootView>:
    orientation: "vertical"
    padding: dp(12)
    spacing: dp(8)

    Label:
        text: "BlackText P2P"
        size_hint_y: None
        height: dp(38)
        font_size: "22sp"

    Label:
        text: root.status_text
        size_hint_y: None
        height: dp(28)

    Label:
        text: "Güvenlik kodu: " + root.security_text
        size_hint_y: None
        height: dp(28)

    BoxLayout:
        size_hint_y: None
        height: dp(44)
        spacing: dp(6)

        TextInput:
            id: address_input
            hint_text: "Bu cihazın IPv6 veya LAN IPv4 adresi"
            multiline: False

        TextInput:
            id: port_input
            text: "24873"
            hint_text: "Port"
            multiline: False
            input_filter: "int"
            size_hint_x: 0.28

    BoxLayout:
        size_hint_y: None
        height: dp(44)
        spacing: dp(6)

        Button:
            text: "Adres Bul"
            on_release: root.detect_address()

        Button:
            text: "Bağlantı Oluştur"
            on_release: root.host()

    Label:
        text: "Davet kodu"
        size_hint_y: None
        height: dp(24)

    TextInput:
        id: invite_output
        text: root.invite_text
        readonly: True
        multiline: True
        size_hint_y: None
        height: dp(82)

    Label:
        text: "Karşı tarafın davet kodu"
        size_hint_y: None
        height: dp(24)

    TextInput:
        id: join_input
        multiline: True
        size_hint_y: None
        height: dp(82)

    BoxLayout:
        size_hint_y: None
        height: dp(44)
        spacing: dp(6)

        Button:
            text: "Bağlan"
            on_release: root.join()

        Button:
            text: "Bağlantıyı Kes"
            on_release: root.stop()

    ScrollView:
        id: chat_scroll
        do_scroll_x: False

        Label:
            id: chat_label
            text: ""
            size_hint_y: None
            height: self.texture_size[1] + dp(20)
            text_size: self.width - dp(12), None
            halign: "left"
            valign: "top"

    BoxLayout:
        size_hint_y: None
        height: dp(48)
        spacing: dp(6)

        TextInput:
            id: message_input
            hint_text: "Mesaj"
            multiline: False
            on_text_validate: root.send_message()

        Button:
            text: "Gönder"
            size_hint_x: 0.30
            on_release: root.send_message()
'''


class RootView(BoxLayout):
    status_text = StringProperty("Hazır")
    security_text = StringProperty("-")
    invite_text = StringProperty("")

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

        self.node = P2PNode(
            on_status=lambda value: Clock.schedule_once(
                lambda dt, value=value: self._set_status(value),
                0,
            ),
            on_message=lambda value: Clock.schedule_once(
                lambda dt, value=value: self._add_message(
                    "Karşı taraf",
                    value,
                ),
                0,
            ),
            on_invite=lambda value: Clock.schedule_once(
                lambda dt, value=value: self._set_invite(value),
                0,
            ),
            on_security=lambda value: Clock.schedule_once(
                lambda dt, value=value: self._set_security(value),
                0,
            ),
        )

        Clock.schedule_once(
            lambda dt: self.detect_address(),
            0,
        )

    def detect_address(self):
        addresses = local_addresses()

        if addresses:
            self.ids.address_input.text = addresses[0]
            self.status_text = "Adres bulundu"
        else:
            self.status_text = "IP adresini elle girin"

    def host(self):
        address = self.ids.address_input.text.strip()
        port_text = self.ids.port_input.text.strip() or "24873"

        if not address:
            self.status_text = "IP adresi girin"
            return

        try:
            port = int(port_text)

            self._clear_session_view()

            self.node.start_host(
                address,
                port,
            )

        except Exception:
            self.status_text = "Adres veya port geçersiz"

    def join(self):
        code = self.ids.join_input.text.strip()

        if not code:
            self.status_text = "Davet kodu girin"
            return

        try:
            self._clear_session_view(
                keep_join=True,
            )

            self.node.connect(code)

        except Exception:
            self.status_text = "Davet kodu geçersiz"

    def send_message(self):
        text = self.ids.message_input.text

        if not text:
            return

        if self.node.send_text(text):
            self._add_message(
                "Sen",
                text,
            )

            self.ids.message_input.text = ""

        else:
            self.status_text = "Mesaj gönderilemedi"

    def stop(self):
        self.node.disconnect()

        self.status_text = "Bağlantı kapatıldı"

        self._clear_session_view()

        self.ids.join_input.text = ""
        self.ids.message_input.text = ""

    def _set_status(self, value):
        if value == "Baglandi":
            self.status_text = "Bağlandı"

            self.invite_text = ""
            self.ids.join_input.text = ""

        elif value == "Baglanti bekleniyor":
            self.status_text = "Bağlantı bekleniyor"

        elif value == "Baglaniyor":
            self.status_text = "Bağlanıyor"

        elif value == "Baglanti kesildi":
            self.status_text = "Bağlantı kesildi"

            self._clear_session_view()

        elif value == "Baglanti kurulamadi":
            self.status_text = "Bağlantı kurulamadı"

            self.security_text = "-"

        else:
            self.status_text = value

    def _set_invite(self, value):
        self.invite_text = value

    def _set_security(self, value):
        self.security_text = value

    def _add_message(self, sender, text):
        label = self.ids.chat_label

        line = f"{sender}: {text}"

        if label.text:
            label.text += "\n\n" + line
        else:
            label.text = line

        Clock.schedule_once(
            lambda dt: setattr(
                self.ids.chat_scroll,
                "scroll_y",
                0,
            ),
            0,
        )

    def _clear_session_view(self, keep_join=False):
        self.security_text = "-"
        self.invite_text = ""

        self.ids.chat_label.text = ""
        self.ids.message_input.text = ""

        if not keep_join:
            self.ids.join_input.text = ""


class BlackTextApp(App):
    def build(self):
        self.title = "BlackText P2P"

        Builder.load_string(KV)

        return RootView()

    def on_start(self):
        try:
            from android.runnable import run_on_ui_thread
            from jnius import autoclass

            @run_on_ui_thread
            def secure_window():
                activity = autoclass(
                    "org.kivy.android.PythonActivity"
                ).mActivity

                params = autoclass(
                    "android.view.WindowManager$LayoutParams"
                )

                activity.getWindow().setFlags(
                    params.FLAG_SECURE,
                    params.FLAG_SECURE,
                )

            secure_window()

        except Exception:
            pass

    def on_stop(self):
        if self.root is not None:
            self.root.node.disconnect()


if __name__ == "__main__":
    BlackTextApp().run()
