'use strict';

/*
 * Capa de datos simulada (version remediada).
 * [FIX-02] Recibe la consulta con marcadores `?` y los valores por separado,
 * como lo haria un driver real con sentencias preparadas.
 */
function getUserByName(sql, params, callback) {
  const fakeRows = [{ id: 1, name: params[0], statement: sql }];
  process.nextTick(() => callback(null, fakeRows));
}

module.exports = { getUserByName };
