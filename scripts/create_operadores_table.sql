-- Crear tabla de operadores para catálogo de emails
IF OBJECT_ID('operador', 'U') IS NULL
BEGIN
    CREATE TABLE operador (
        id INT IDENTITY(1,1) PRIMARY KEY,
        nombre NVARCHAR(120) NOT NULL,
        email NVARCHAR(200) NOT NULL,
        activo BIT NOT NULL DEFAULT 1,
        created_at DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME()
    );
    CREATE INDEX IX_operador_activo_nombre ON operador (activo, nombre);
    CREATE INDEX IX_operador_email ON operador (email);
END
