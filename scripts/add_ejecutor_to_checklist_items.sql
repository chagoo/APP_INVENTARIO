-- Agrega columna 'ejecutor' a la tabla de items del checklist (SQL Server)
-- Solo se ejecuta si la columna no existe. Ajusta el nombre de la tabla si difiere.

IF COL_LENGTH('operation_checklist_item', 'ejecutor') IS NULL
BEGIN
    ALTER TABLE operation_checklist_item
    ADD ejecutor NVARCHAR(200) NULL;  -- Quién ejecuta / da seguimiento a la actividad
END
GO

-- Crear índice opcional para acelerar búsquedas/filtrado por ejecutor
IF NOT EXISTS (
    SELECT 1 FROM sys.indexes i WHERE i.name = 'IX_operation_checklist_item_ejecutor'
)
BEGIN
    CREATE INDEX IX_operation_checklist_item_ejecutor
    ON operation_checklist_item (ejecutor);
END
GO

/*
SQLite (si usas el archivo data.sqlite) NO soporta ALTER TABLE ADD COLUMN con chequeo de existencia.
Para SQLite puedes ejecutar simplemente (se ignora si ya existe):

ALTER TABLE operation_checklist_item ADD COLUMN ejecutor TEXT;

Si ya existe lanzará error; en ese caso verifica con:
PRAGMA table_info(operation_checklist_item);

*/
