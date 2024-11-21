#!/usr/bin/env python3

import json
import jwt
import base64
from datetime import datetime, timedelta, timezone

import tkinter as tk
from tkinter import TclError, ttk
from tkinter.messagebox import showinfo


def b64decode(s):
    return base64.urlsafe_b64decode(s + '=' * (4 - len(s) % 4))

def b64encode(s):
    return base64.urlsafe_b64encode(s).replace('=', '')


class VerifierException(Exception):
    ...


class UI:
    def __init__(self):
        self.verifier = JwtVerifier()

        self.left_frame         = None
        self.right_frame        = None
        self.encoded_field      = None
        self.secret_field       = None
        self.privkey_field      = None
        self.verification_label = None
        self.expiration_label   = None
        self.header_field       = None
        self.payload_field      = None

        self.create_main_window()

    def create_main_window(self):
        root = tk.Tk()
        root.title('JWT Verifier')
        root.resizable(0, 0)

        root.columnconfigure(0, weight=3)
        root.columnconfigure(1, weight=1)

        self.left_frame = self.create_left_frame(root)
        self.left_frame.grid(column=0, row=0)

        self.right_frame = self.create_right_frame(root)
        self.right_frame.grid(column=1, row=0)

        self.do_decode()
        root.mainloop()

    def create_left_frame(self, container):
        frame = ttk.Frame(container)

        frame.columnconfigure(0, weight=1)

        default_encoded_token = ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzd"
                                +"WIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9"
                                +"lIiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjE4MTYyM"
                                +"zkwMjJ9.DYTQuvkWQ3CJi34H7pvb21dtcnVZPbTzIR"
                                +"JLXZO_UIg")

        encoded_text = tk.StringVar()
        encoded_text.trace("w", lambda name, index, mode,
                           sv=encoded_text: self.do_decode())

        ttk.Label(frame, text="Encoded Token").grid(column=0,
                                                    row=0,
                                                    sticky=tk.W)
        self.encoded_field = ScrolledText(frame,
                                          height=10,
                                          textvariable=encoded_text,
                                          wrap=tk.WORD)
        self.encoded_field.grid(column=0, row=1)
        self.encoded_field.insert(tk.INSERT, default_encoded_token)

        secret_label_text = "HMAC Secret / JWKS URL / Public Key Path"
        secret_label = ttk.Label(frame, text=secret_label_text)
        secret_label.grid(column=0, row=2, sticky=tk.W)

        self.secret_field = tk.Entry(frame, width=72)
        self.secret_field.grid(column=0, row=3)
        self.secret_field.insert(tk.INSERT, "your-256-bit-secret")
        self.secret_field.bind('<Any-KeyRelease>', lambda _ : self.do_encode())

        privkey_label_text = "Private Key Path (if RSA)"
        privkey_label = ttk.Label(frame, text=privkey_label_text)
        privkey_label.grid(column=0, row=4, sticky=tk.W)

        self.privkey_field = tk.Entry(frame, width=72)
        self.privkey_field.grid(column=0, row=5)
        self.privkey_field.bind('<Any-KeyRelease>', lambda _ : self.do_encode())

        self.verification_label = ttk.Label(frame, text="Verification")
        self.verification_label.grid(column=0, row=6, sticky=tk.W)

        self.expiration_label = ttk.Label(frame, text="Expiration")
        self.expiration_label.grid(column=0, row=7, sticky=tk.W)

        (ttk.Button(frame, text="Verify", command=self.click_verify)
            .grid(column=0, row=8))

        return frame

    def create_right_frame(self, container):
        frame = ttk.Frame(container)

        frame.columnconfigure(0, weight=1)

        header_text = tk.StringVar()
        header_text.trace("w", lambda name, index, mode,
                          sv=header_text: self.do_encode())

        payload_text = tk.StringVar()
        payload_text.trace("w", lambda name, index, mode,
                           sv=payload_text: self.do_encode())

        ttk.Label(frame, text="Header").grid(column=0, row=0, sticky=tk.W)
        self.header_field = ScrolledText(frame,
                                         height=15,
                                         textvariable=header_text,
                                         wrap=tk.WORD)
        self.header_field.grid(column=0, row=1)

        ttk.Label(frame, text="Payload").grid(column=0, row=2, sticky=tk.W)
        self.payload_field = ScrolledText(frame,
                                          height=15,
                                          textvariable=payload_text,
                                          wrap=tk.WORD)
        self.payload_field.grid(column=0, row=3)

        return frame

    def display_encoded_jwt(self, encoded_jwt):
        self.encoded_field.delete("1.0", tk.END)
        self.encoded_field.insert(tk.INSERT, encoded_jwt)

    def display_header(self, header):
        self.header_field.delete("1.0", tk.END)
        self.header_field.insert(tk.INSERT, header)

    def display_payload(self, payload):
        self.payload_field.delete("1.0", tk.END)
        self.payload_field.insert(tk.INSERT, payload)

    def display_verification(self, status):
        if status is True:
            self.verification_label = tk.Label(self.left_frame,
                      text="Verification: Verified",
                      fg= "#338822")
        else:
            self.verification_label = tk.Label(self.left_frame,
                      text="Verification: Failed    ",
                      fg= "#CC0000")

        self.verification_label.grid(column=0, row=6, sticky=tk.W)

    def display_expiration(self, status):
        if status is None:
            self.expiration_label = tk.Label(self.left_frame,
                      text="Expiration: No expiration")

        elif status is False:
            self.expiration_label = tk.Label(self.left_frame,
                      text="Expiration: Verified           ",
                      fg= "#338822")
        else:
            self.expiration_label = tk.Label(self.left_frame,
                      text="Expiration: Failed             ",
                      fg= "#CC0000")

        self.expiration_label.grid(column=0, row=7, sticky=tk.W)

    def do_encode(self):
        header = self.header_field.get("1.0", tk.END).replace("\n", "")
        self.load_header()
        payload = self.payload_field.get("1.0", tk.END).replace("\n", "")
        self.load_payload()

        self.load_key()
        jws = self.verifier.encode_jwt(header, payload)
        self.display_encoded_jwt(jws)

    def do_decode(self):
        token = self.encoded_field.get("1.0", tk.END).replace("\n", "")

        try:
            self.verifier.decode_jwt(token)
        except VerifierException as e:
            showinfo("Error", e.message)

        self.display_header(json.dumps(self.verifier.header))
        self.display_payload(json.dumps(self.verifier.payload))

    def click_verify(self):
        self.do_decode()
        self.load_key()
        self.display_verification(self.verifier.verify_signature())
        self.display_expiration(self.verifier.verify_expiration())

    def load_key(self):
        key = self.secret_field.get().replace("\n", "")
        self.verifier.load_key(key)

    def load_private_key(self):
        key = self.privkey_field.get("1.0", tk.END).replace("\n", "")
        self.verifier.load_key(key, private=True)

    def load_header(self):
        header = self.header_field.get("1.0", tk.END).replace("\n", "")
        self.verifier.load_header(header)

    def load_payload(self):
        payload = self.payload_field.get("1.0", tk.END).replace("\n", "")
        self.verifier.load_payload(payload)


class JwtVerifier:
    def __init__(self):
        self.raw_token = ""
        self.verifying_key = None
        self.signing_key = None
        self.header = ""
        self.payload = ""
        self.signature = ""

    def decode_jwt(self, token):
        self.raw_token = token

        self.load_header(json.dumps(jwt.get_unverified_header(token)))
        self.load_payload(json.dumps(
                jwt.decode(token, options={"verify_signature": False})))

    def load_header(self, header):
        self.header = json.loads(header)

    def load_payload(self, payload):
        self.payload = json.loads(payload)

    def get_algorithm(self):
        if self.raw_token == "" and self.header == "":
            raise VerifierException("Error: No token")

        return self.header["alg"].upper()

    def load_key(self, keystring, private=False):
        algorithm = self.get_algorithm()

        if algorithm == "NONE":
            return

        if algorithm.startswith("HS"):
            self.load_hmac_secret(keystring)
            return

        if private:
            if algorithm.startswith("http"):
                self.load_private_key_from_url(keystring)
                return

            else:
                self.load_private_key_from_path(keystring)
                return

        if algorithm.startswith("http"):
            self.load_public_key_from_url(keystring)
            return

        else:
            self.load_public_key_from_path(keystring)
            return

    def load_hmac_secret(self, secret):
        self.verifying_key = secret.encode("utf-8")
        self.signing_key = self.verifying_key

    def load_public_key_from_path(self, key_path):
        with open(key_path, 'rb') as fh:
            self.verifying_key = fh.read()

    def load_private_key_from_path(self, key_path):
        with open(key_path, 'rb') as fh:
            self.signing_key = fh.read()

    def load_public_key_from_url(self, key_path):
        jwks_client = PyJWKClient(key_path)
        self.signing_key = jwks_client.get_signing_key_from_jwt(self.raw_token)

    def verify_signature(self):
        result = True
        try:
            jwt.decode(self.raw_token,
                       self.verifying_key,
                       algorithms=[self.get_algorithm()])
        except jwt.InvalidSignatureError:
            result = False
        except jwt.ExpiredSignatureError:
            pass
        return result

    def verify_expiration(self):
        if "exp" not in self.payload:
            return None

        result = None
        try:
            jwt.decode(self.raw_token,
                       self.verifying_key,
                       algorithms=[self.get_algorithm()])
            result = False
        except jwt.ExpiredSignatureError:
            result = True
        return result

    def encode_jwt(self, header, payload):
        self.load_header(header)
        self.load_payload(payload)
        jws = jwt.encode(self.payload,
                         self.signing_key,
                         self.get_algorithm(),
                         headers=self.header)
        return jws

class ScrolledText(tk.Frame):
    def __init__(self, parent, textvariable, *args, **kwargs):
        tk.Frame.__init__(self, parent)
        self.text = tk.Text(self, *args, **kwargs)
        self.vsb = tk.Scrollbar(self, orient="vertical", command=self.text.yview)
        self.text.configure(yscrollcommand=self.vsb.set)
        self.vsb.pack(side="right", fill="y")
        self.text.pack(side="left", fill="both", expand=True)
        self.text.bind("<KeyRelease>", self.text_changed)
        self.text.bind('<Delete>', self.text_del)
        self.text.bind('<BackSpace>', self.text_backspace)
        self.textvariable = textvariable
        self.text.bind('<Enter>', self.enter)
        self.text.bind('<Leave>', self.leave)

    def get(self, *args, **kwargs):
        return self.text.get(*args, **kwargs)

    def configure(self, **kwargs):
        self.state(kwargs.get('state',None))

    def state(self, state):
        self.text.configure(state=state)

    def delete(self, first, last=None):
        self.text.delete(first, last)

    def insert(self, location, item):
        self.text.insert(location, item)


    def enter(self, event):
        self.text.config(cursor="hand2")

    def leave(self, event):
        self.text.config(cursor="")

    def text_changed(self, key):
        if str(self.text.cget('state')) == 'normal':
            self.textvariable.set('')
            self.textvariable.set(self.text.get('1.0', tk.END))

    def text_backspace(self, key):
        self.textvariable.set(self.text.get('1.0', self.text.index(tk.CURRENT + ' -1 chars')))

    def text_del(self, key):
        self.textvariable.set(self.text.get('1.0', self.text.index(tk.INSERT)))


def main():
    ui = UI()


if __name__ == "__main__":
    main()
