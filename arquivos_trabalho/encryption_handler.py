# Adicionar após imports

from cryptography.fernet import Fernet
import base64

class EncryptionHandler:
    """Gerencia criptografia/descriptografia de dados"""
    
    def __init__(self, key=None):
        """
        key: chave criptográfica (32 bytes base64)
        Se None, gera uma nova chave
        """
        if key is None:
            self.key = Fernet.generate_key()
        else:
            self.key = key
        self.cipher = Fernet(self.key)
    
    def encrypt(self, data):
        """
        Criptografa dados
        data: bytes
        return: bytes criptografados
        """
        if isinstance(data, str):
            data = data.encode()
    
        encrypted = self.cipher.encrypt(data)
        return encrypted
    
    def decrypt(self, encrypted_data):
        """
        Descriptografa dados
        encrypted_data: bytes criptografados
        return: bytes descriptografados
        """
        if isinstance(encrypted_data, str):
            encrypted_data = encrypted_data.encode()
    
        decrypted = self.cipher.decrypt(encrypted_data)
        return decrypted
    
    def get_key(self):
        """Retorna chave em formato base64 para transmissão"""
        return self.key
    
    def get_key_string(self):
        """Retorna chave como string (para debug)"""
        return self.key.decode()
    
    # MELHORIA: método estático
    @staticmethod
    def generate_new_key():
        """Gera uma nova chave Fernet"""
        return Fernet.generate_key()