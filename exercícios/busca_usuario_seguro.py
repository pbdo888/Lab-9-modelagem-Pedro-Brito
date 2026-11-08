"""Exercício 9.3: busca de usuário refatorada contra Injeção (A05:2025)."""
import re
import sqlite3
from contextlib import closing

CAMINHO_BANCO = "usuarios.db"
TAMANHO_MAXIMO_EMAIL = 254
PADRAO_EMAIL = re.compile(
    r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}"
)


def validar_email(email_digitado):
    """Devolve o e-mail sem espaços nas pontas ou levanta ValueError se for inválido."""
    if not isinstance(email_digitado, str):
        raise ValueError("E-mail inválido.")

    email = email_digitado.strip()
    # fullmatch exige que a string inteira siga o padrão, do início ao fim.
    if len(email) > TAMANHO_MAXIMO_EMAIL or not PADRAO_EMAIL.fullmatch(email):
        raise ValueError("E-mail inválido.")

    return email


def busca_usuario_por_email(email_digitado, caminho_banco=CAMINHO_BANCO):
    """Devolve (nome, email) do usuário encontrado ou None."""
    email = validar_email(email_digitado)

    # closing() garante que a conexão seja fechada mesmo se ocorrer um erro.
    with closing(sqlite3.connect(caminho_banco)) as conexao:
        # O "?" envia o e-mail como DADO: ele nunca vira parte do comando SQL.
        cursor = conexao.execute(
            "SELECT nome, email FROM usuarios WHERE email = ?",
            (email,),
        )
        return cursor.fetchone()
