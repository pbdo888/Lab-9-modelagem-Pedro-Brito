"""Testes do Exercício 9.3. Execute nesta pasta: python -m unittest -v"""
import contextlib
import io
import os
import sqlite3
import tempfile
import unittest
from contextlib import closing
from unittest import mock

import busca_usuario_seguro as seguro
import busca_usuario_vulneravel as vulneravel

PAYLOAD_INJECAO = "' OR '1'='1"


class BaseComBanco(unittest.TestCase):
    def setUp(self):
        pasta = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(pasta.cleanup)
        self.banco = os.path.join(pasta.name, "usuarios.db")
        with closing(sqlite3.connect(self.banco)) as conexao:
            conexao.execute("CREATE TABLE usuarios (nome TEXT, email TEXT)")
            conexao.executemany(
                "INSERT INTO usuarios VALUES (?, ?)",
                [("Ana", "ana@exemplo.com"), ("Bruno", "bruno@exemplo.com")],
            )
            conexao.commit()


class TesteCodigoVulneravel(BaseComBanco):
    def test_payload_devolve_usuario_sem_conhecer_o_email(self):
        conexao = sqlite3.connect(self.banco)
        self.addCleanup(conexao.close)

        with mock.patch("sqlite3.connect", return_value=conexao):
            with contextlib.redirect_stdout(io.StringIO()):
                resultado = vulneravel.busca_usuario_por_email(PAYLOAD_INJECAO)

        self.assertEqual(resultado, ("Ana", "ana@exemplo.com"))


class TesteCodigoSeguro(BaseComBanco):
    def test_encontra_usuario_existente(self):
        resultado = seguro.busca_usuario_por_email("bruno@exemplo.com", self.banco)
        self.assertEqual(resultado, ("Bruno", "bruno@exemplo.com"))

    def test_remove_espacos_nas_pontas(self):
        resultado = seguro.busca_usuario_por_email("  ana@exemplo.com ", self.banco)
        self.assertEqual(resultado, ("Ana", "ana@exemplo.com"))

    def test_email_inexistente_devolve_none(self):
        self.assertIsNone(
            seguro.busca_usuario_por_email("nao@exemplo.com", self.banco)
        )

    def test_validacao_rejeita_entradas_invalidas(self):
        entradas = [
            PAYLOAD_INJECAO,
            "ana@exemplo.com' --",
            "ana@exemplo.com\nDROP",
            "sem-arroba",
            "",
            None,
            "a" * 250 + "@exemplo.com",
        ]
        for entrada in entradas:
            with self.subTest(entrada=entrada):
                with self.assertRaises(ValueError):
                    seguro.busca_usuario_por_email(entrada, self.banco)

    def test_parametrizacao_protege_mesmo_sem_a_validacao(self):
        # Desliga a validação para provar que o "?" neutraliza o ataque sozinho.
        with mock.patch.object(seguro, "validar_email", side_effect=lambda e: e):
            resultado = seguro.busca_usuario_por_email(PAYLOAD_INJECAO, self.banco)
        self.assertIsNone(resultado)


if __name__ == "__main__":
    unittest.main()
