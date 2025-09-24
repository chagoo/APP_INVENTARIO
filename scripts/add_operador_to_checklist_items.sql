-- Agrega columna 'operador' a la tabla de items del checklist en SQL Server
-- Ajusta el nombre del esquema/tabla si difiere en tu base

IF COL_LENGTH('operation_checklist_item', 'operador') IS NULL
BEGIN
    ALTER TABLE operation_checklist_item
    ADD operador NVARCHAR(200) NULL;
END

-- Índice opcional si se busca por operador frecuentemente
IF NOT EXISTS (
    SELECT 1 FROM sys.indexes i WHERE i.name = 'IX_operation_checklist_item_operador'
)
BEGIN
    CREATE INDEX IX_operation_checklist_item_operador
    ON operation_checklist_item (operador);
END
