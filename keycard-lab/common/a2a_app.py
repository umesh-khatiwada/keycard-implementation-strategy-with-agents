"""Build a Keycard-protected A2A agent service (same composition as the
official keycardai-a2a example): agent card, RFC 9728 metadata, and a
/a2a/jsonrpc mount that rejects any token whose audience is not this agent."""
from __future__ import annotations

from a2a.server.agent_execution import AgentExecutor
from a2a.server.request_handlers import DefaultRequestHandler
from a2a.server.routes import create_agent_card_routes, create_jsonrpc_routes
from a2a.server.tasks import InMemoryTaskStore
from a2a.types import Message, Part, Role
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.authentication import AuthenticationMiddleware
from starlette.routing import Mount

from keycardai.a2a import AgentServiceConfig, KeycardServerCallContextBuilder, build_agent_card_from_config
from keycardai.oauth.server.credentials import ClientSecret
from keycardai.starlette import AuthProvider, KeycardAuthBackend, keycard_on_error
from keycardai.starlette.routers.metadata import (
    well_known_authorization_server_route,
    well_known_protected_resource_route,
)


def agent_text(text: str) -> Message:
    return Message(role=Role.ROLE_AGENT, parts=[Part(text=text)])


def build_app(config: AgentServiceConfig, executor: AgentExecutor) -> Starlette:
    auth_provider = AuthProvider(
        zone_url=config.auth_server_url,
        server_name=config.service_name,
        server_url=config.identity_url,
        audience=config.identity_url,  # tokens minted for another agent are rejected
        application_credential=ClientSecret((config.client_id, config.client_secret)),
    )
    card = build_agent_card_from_config(config)
    handler = DefaultRequestHandler(agent_executor=executor, task_store=InMemoryTaskStore(), agent_card=card)
    return Starlette(routes=[
        *create_agent_card_routes(agent_card=card),
        well_known_protected_resource_route(
            issuer=config.auth_server_url,
            resource="/.well-known/oauth-protected-resource{resource_path:path}"),
        well_known_authorization_server_route(
            issuer=config.auth_server_url,
            resource="/.well-known/oauth-authorization-server{resource_path:path}"),
        Mount("/a2a",
              routes=create_jsonrpc_routes(request_handler=handler, rpc_url="/jsonrpc",
                                           context_builder=KeycardServerCallContextBuilder()),
              middleware=[Middleware(AuthenticationMiddleware,
                                     backend=KeycardAuthBackend(auth_provider.get_token_verifier(),
                                                                require_authentication=True),
                                     on_error=keycard_on_error)]),
    ])
