import copy
import json
import re
from collections import defaultdict
from typing import Any, Callable, Dict, Optional, Type

from spectree import SpecTree, Tag
from spectree._types import ModelType, NamingStrategy, NestedNamingStrategy
from spectree.plugins import BasePlugin
from spectree.utils import (
    default_after_handler,
    default_before_handler,
    get_model_key,
    get_nested_key,
    get_security,
    parse_comments,
    parse_name,
    parse_params,
    parse_request,
    parse_resp,
)


class SpecWrapper(SpecTree):
    _schemas = defaultdict(lambda: defaultdict(dict))
    _schemas_links = {}

    def __init__(
        self,
        backend_name: str = "base",
        backend: Optional[Type[BasePlugin]] = None,
        app: Any = None,
        before: Callable = default_before_handler,
        after: Callable = default_after_handler,
        validation_error_status: int = 422,
        validation_error_model: Optional[ModelType] = None,
        naming_strategy: NamingStrategy = get_model_key,
        nested_naming_strategy: NestedNamingStrategy = get_nested_key,
        clear: bool = True,
        beauty: bool = True,
        **kwargs: Any,
    ):
        """
        Инициализация SpecWrapper.
        Дополнительные параметры:
            clear (bool): Флаг для удаления дубликатов схем
            beauty (bool): Флаг для улучшения отображения
        """
        super().__init__(
            backend_name,
            backend,
            app,
            before,
            after,
            validation_error_status,
            validation_error_model,
            naming_strategy,
            nested_naming_strategy,
            **kwargs,
        )
        self.clear = clear
        self.beauty = beauty

    def _beatify_schemas(self, schemas: dict):
        """
        Создает HTML-форматированное представление схем.
        Args:
            schemas (dict): Словарь схем
        Returns:
            str: HTML-строка со ссылками на схемы
        """
        result = "<br/>"
        for key, value in schemas.items():
            result += (
                f"<b>{key}</b>: <a href='{self._schemas_links[value]}'>{value}</a><br/>"
            )
        result += "<br/>"
        return result

    def _create_links(self, schemas: dict):
        """
        Создает ссылки для схем.
        Args:
            schemas (dict): Словарь схем
        """
        for key in schemas.keys():
            cleaned_key = self._get_cleaned_name(key)
            self._schemas_links[cleaned_key] = f"/schemas/{key}"

    def _generate_spec(self) -> Dict[str, Any]:
        """
        Генерирует OpenAPI спецификацию.
        Returns:
            Dict[str, Any]: Спецификация OpenAPI
        """
        routes: Dict[str, Dict] = defaultdict(dict)
        tags = {}
        for route in self.backend.find_routes():
            for method, func in self.backend.parse_func(route):
                if self.backend.bypass(func, method) or self.bypass(func):
                    continue

                path_parameter_descriptions = getattr(
                    func, "path_parameter_descriptions", None
                )
                path, parameters = self.backend.parse_path(
                    route, path_parameter_descriptions
                )

                name = parse_name(func)
                summary, desc = parse_comments(func)
                func_tags = getattr(func, "tags", ())

                for tag in func_tags:
                    if str(tag) not in tags:
                        tags[str(tag)] = (
                            tag.model_dump() if isinstance(tag, Tag) else {"name": tag}
                        )

                keys = ["query", "headers", "cookies", "resp"]
                for key in keys:
                    if hasattr(func, key):
                        if key == "resp":
                            for code, model in getattr(func, key).code_models.items():
                                self._schemas[path][method.lower()][
                                    code.replace("HTTP_", "")
                                ] = model.__name__
                        else:
                            self._schemas[path][method.lower()][key.capitalize()] = (
                                self._get_cleaned_name(getattr(func, key))
                            )

                routes[path][method.lower()] = {
                    "summary": summary or f"{name} <{method}>",
                    "operationId": self.backend.get_func_operation_id(
                        func, path, method
                    ),
                    "description": desc or "",
                    "tags": [str(x) for x in getattr(func, "tags", ())],
                    "parameters": parse_params(func, parameters[:], self.models),
                    "responses": parse_resp(func, self.naming_strategy),
                }

                security = getattr(func, "security", None)
                if security is not None:
                    routes[path][method.lower()]["security"] = get_security(security)

                deprecated = getattr(func, "deprecated", False)
                if deprecated:
                    routes[path][method.lower()]["deprecated"] = deprecated

                request_body = parse_request(func)
                if request_body:
                    routes[path][method.lower()]["requestBody"] = request_body

        spec: Dict[str, Any] = {
            "openapi": self.config.openapi_version,
            "info": self.config.openapi_info(),
            "tags": list(tags.values()),
            "paths": {**routes},
            "components": {
                "schemas": {**self.models, **self._get_model_definitions()},
            },
        }

        if self.config.servers:
            spec["servers"] = [
                server.model_dump(exclude_none=True, mode="json")
                for server in self.config.servers
            ]

        if self.config.security_schemes:
            spec["components"]["securitySchemes"] = {
                scheme.name: scheme.data.model_dump(
                    exclude_none=True, by_alias=True, mode="json"
                )
                for scheme in self.config.security_schemes
            }

        spec["security"] = get_security(self.config.security)

        self._create_links(spec["components"]["schemas"])
        return spec

    def _update_references(self, obj: Any, schema_references: dict):
        """
        Обновляет ссылки на схемы.
        Args:
            obj (Any): Объект для обновления
            schema_references (dict): Словарь с ссылками на схемы
        """
        if isinstance(obj, dict):
            for key, value in obj.items():
                if key == "$ref" and isinstance(value, str):
                    ref_name = value.split("/")[-1]
                    if ref_name in schema_references:
                        obj[key] = value.replace(ref_name, schema_references[ref_name])
                else:
                    self._update_references(value, schema_references)
        elif isinstance(obj, list):
            for item in obj:
                self._update_references(item, schema_references)

    def beautify(self, specs: dict):
        """
        Добавляет ссылки на схемы в спецификацию.
        Args:
            specs (dict): Спецификация для улучшения
        Returns:
            dict: Спецификация с ссылками на схемы
        """
        for path, methods in specs["paths"].items():
            path_schemas = self._schemas[path]
            for method, details in methods.items():
                method_schemas = path_schemas[method]
                details["summary"] = f"{path}"
                details["description"] += self._beatify_schemas(method_schemas)
        return specs

    def remove_doubles(self, specs: dict):
        """
        Удаляет дублирующиеся схемы.
        Args:
            specs (dict): Исходная спецификация
        Returns:
            dict: Спецификация без дубликатов
        """
        unique_schemas = {}
        schema_references = {}

        for schema_name, schema_def in specs["components"]["schemas"].items():
            schema_str = json.dumps(schema_def, sort_keys=True)

            if schema_str not in unique_schemas:
                unique_schemas[schema_str] = schema_name
                schema_references[schema_name] = schema_name
            else:
                schema_references[schema_name] = unique_schemas[schema_str]
        self._update_references(specs["paths"], schema_references)
        self._update_references(specs["components"], schema_references)

        deduplicated_schemas = {
            name: specs["components"]["schemas"][name]
            for name in schema_references.values()
        }
        specs["components"]["schemas"] = dict(
            sorted(deduplicated_schemas.items(), key=lambda x: x[0])
        )
        return specs

    @property
    def spec(self):
        """
        Свойство для получения спецификации.
        Returns:
            Dict: Обработанная спецификация OpenAPI
        """
        specs: Dict[str, Any] = copy.deepcopy(super().spec)

        if self.clear:
            specs = self.remove_doubles(specs)
        if self.beauty:
            specs = self.beautify(specs)
        return specs

    @staticmethod
    def _get_cleaned_name(schema_name: str):
        """
        Очищает имя схемы от хеш-суффикса.
        Args:
            schema_name (str): Исходное имя схемы
        Returns:
            str: Очищенное имя схемы
        """
        pattern = re.compile(r"\.[\da-f]{6,}$")
        new_name = pattern.sub("", schema_name)
        return new_name
