
from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.scrollview import ScrollView
from kivy.uix.label import Label
from kivy.uix.button import Button
from kivy.uix.textinput import TextInput
from mnemonic import Mnemonic
import hashlib
import ecdsa
import base58
from eth_account import Account
import requests

class WalletBox(BoxLayout):
    def __init__(self, **kwargs):
        super().__init__(orientation='vertical', spacing=10, padding=10, **kwargs)
        self.mnemo = Mnemonic("english")

        self.input_label = Label(text="Number of Wallets:", size_hint_y=None, height=40)
        self.add_widget(self.input_label)

        self.input_field = TextInput(text="1", multiline=False, size_hint_y=None, height=40)
        self.add_widget(self.input_field)

        self.generate_button = Button(text="Generate Wallets", size_hint_y=None, height=50, on_press=self.generate_wallets)
        self.add_widget(self.generate_button)

        self.output_label = Label(text="", size_hint_y=None, halign="left", valign="top", text_size=(400, None))
        scroll = ScrollView(size_hint=(1, 1))
        scroll.add_widget(self.output_label)
        self.add_widget(scroll)

    def generate_wallets(self, instance):
        try:
            count = int(self.input_field.text)
        except:
            count = 1

        result = ""
        for i in range(1, count + 1):
            phrase = self.mnemo.generate(strength=128)
            seed = self.mnemo.to_seed(phrase)

            btc = self.generate_btc_address(seed)
            btc_bal = self.check_balance("btc", btc)

            eth = self.generate_eth_address(seed)
            eth_bal = self.check_balance("eth", eth)

            ltc = self.generate_ltc_address(seed)
            ltc_bal = self.check_balance("ltc", ltc)

            doge = self.generate_doge_address(seed)
            doge_bal = self.check_balance("doge", doge)

            trx = self.generate_trx_address(seed)
            trx_bal = self.check_balance("trx", trx)

            result += f"--- Wallet {i} ---\n"
            result += f"Seed Phrase: {phrase}\n"
            result += f"BTC Address: {btc} | Balance: {btc_bal}\n"
            result += f"ETH Address: {eth} | Balance: {eth_bal}\n"
            result += f"LTC Address: {ltc} | Balance: {ltc_bal}\n"
            result += f"DOGE Address: {doge} | Balance: {doge_bal}\n"
            result += f"TRX Address: {trx} | Balance: {trx_bal}\n"
            result += "------------------------\n\n"

        self.output_label.text = result

    def generate_btc_address(self, seed):
        private_key = seed[:32]
        sk = ecdsa.SigningKey.from_string(private_key, curve=ecdsa.SECP256k1)
        vk = sk.verifying_key
        pubkey = b'\x02' + vk.to_string()[:32] if vk.to_string()[-1] % 2 == 0 else b'\x03' + vk.to_string()[:32]
        sha = hashlib.sha256(pubkey).digest()
        ripemd = hashlib.new('ripemd160')
        ripemd.update(sha)
        hashed = ripemd.digest()
        prefix = b'\x00' + hashed
        checksum = hashlib.sha256(hashlib.sha256(prefix).digest()).digest()[:4]
        return base58.b58encode(prefix + checksum).decode()

    def generate_eth_address(self, seed):
        private_key = seed[:32].hex()
        acct = Account.from_key(private_key)
        return acct.address

    def generate_ltc_address(self, seed):
        private_key = seed[:32]
        sk = ecdsa.SigningKey.from_string(private_key, curve=ecdsa.SECP256k1)
        vk = sk.verifying_key
        pubkey = b'\x02' + vk.to_string()[:32] if vk.to_string()[-1] % 2 == 0 else b'\x03' + vk.to_string()[:32]
        sha = hashlib.sha256(pubkey).digest()
        ripemd = hashlib.new('ripemd160')
        ripemd.update(sha)
        hashed = ripemd.digest()
        prefix = b'\x30' + hashed
        checksum = hashlib.sha256(hashlib.sha256(prefix).digest()).digest()[:4]
        return base58.b58encode(prefix + checksum).decode()

    def generate_doge_address(self, seed):
        private_key = seed[:32]
        sk = ecdsa.SigningKey.from_string(private_key, curve=ecdsa.SECP256k1)
        vk = sk.verifying_key
        pubkey = b'\x02' + vk.to_string()[:32] if vk.to_string()[-1] % 2 == 0 else b'\x03' + vk.to_string()[:32]
        sha = hashlib.sha256(pubkey).digest()
        ripemd = hashlib.new('ripemd160')
        ripemd.update(sha)
        hashed = ripemd.digest()
        prefix = b'\x1e' + hashed
        checksum = hashlib.sha256(hashlib.sha256(prefix).digest()).digest()[:4]
        return base58.b58encode(prefix + checksum).decode()

    def generate_trx_address(self, seed):
        private_key = seed[:32].hex()
        acct = Account.from_key(private_key)
        return "T" + acct.address[2:]

    def check_balance(self, coin, address):
        try:
            if coin == "btc":
                url = f"https://blockstream.info/api/address/{address}"
                r = requests.get(url)
                d = r.json()
                return d['chain_stats']['funded_txo_sum'] / 1e8
            elif coin == "eth":
                url = f"https://api.blockcypher.com/v1/eth/main/addrs/{address}/balance"
                r = requests.get(url)
                d = r.json()
                return d['balance'] / 1e18
            elif coin == "ltc":
                url = f"https://chain.so/api/v2/get_address_balance/LTC/{address}"
                r = requests.get(url)
                d = r.json()
                return float(d['data']['confirmed_balance'])
            elif coin == "doge":
                url = f"https://sochain.com/api/v2/get_address_balance/DOGE/{address}"
                r = requests.get(url)
                d = r.json()
                return float(d['data']['confirmed_balance'])
            elif coin == "trx":
                url = f"https://apilist.tronscan.org/api/account?address={address}"
                r = requests.get(url)
                d = r.json()
                return d.get('balance', 0) / 1e6
        except:
            return "Error"

class WalletApp(App):
    def build(self):
        return WalletBox()

if __name__ == '__main__':
    WalletApp().run()
