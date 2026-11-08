# Código ORIGINAL do enunciado, mantido sem alterações para comparação.
# NÃO USE: vulnerável a Injeção (A05:2025).
import sqlite3


def busca_usuario_por_email(email_digitado):
    conexao = sqlite3.connect('usuarios.db')
    cursor = conexao.cursor()

    query = "SELECT nome, email FROM usuarios WHERE email = '" + email_digitado + "'"

    print(f"Executando query: {query}")
    cursor.execute(query)

    return cursor.fetchone()
