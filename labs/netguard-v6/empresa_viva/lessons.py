"""Falhas didáticas SOMENTE em memória, sem listener, subprocesso ou destino de rede.

O servidor público/local nunca instancia estas classes como sua central de chamados.
O executor compara cenários fixos; entradas do navegador não selecionam uma falha arbitrária.
"""
from .helpdesk import Helpdesk


class MissingOwnerCheck(Helpdesk):
    def can_read(self, identity, ticket):
        return True  # Falha intencional: uma sessão não autoriza todo recurso.


class MissingAdminCheck(Helpdesk):
    def can_close(self, identity):
        return True  # Falha intencional: botão escondido não verifica o papel na API.


class MissingLoginLimit(Helpdesk):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.budget = _NoLimitForFixedLesson()


class _NoLimitForFixedLesson:
    def allow(self, source, username):
        return True

    def success(self, source, username):
        pass
