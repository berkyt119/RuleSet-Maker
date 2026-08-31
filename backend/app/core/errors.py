from fastapi import HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse


class AppError(HTTPException):
    def __init__(self, status_code: int, code: str, message: str):
        super().__init__(status_code=status_code, detail={"code": code, "message": message})


def error_response(status_code: int, code: str, message: str) -> JSONResponse:
    return JSONResponse(status_code=status_code, content={"error": {"code": code, "message": message}})


async def http_exception_handler(_request: Request, exc: HTTPException) -> JSONResponse:
    if isinstance(exc.detail, dict) and "code" in exc.detail and "message" in exc.detail:
        return error_response(exc.status_code, exc.detail["code"], exc.detail["message"])
    return error_response(exc.status_code, "HTTP_ERROR", str(exc.detail))


async def validation_exception_handler(_request: Request, _exc: RequestValidationError) -> JSONResponse:
    return error_response(422, "VALIDATION_ERROR", "Некорректные параметры запроса.")


async def unhandled_exception_handler(_request: Request, _exc: Exception) -> JSONResponse:
    return error_response(500, "INTERNAL_ERROR", "Внутренняя ошибка приложения.")
