# Contratos de Dedalo (bloque 0)

Qué hace la primera versión, qué puede tocar cada módulo y qué estados usan. Si el código contradice este documento, se corrige uno de los dos; no se deja la diferencia.

## 0.1 Primera versión

**Incluye**

- Auditorías: un cliente o proyecto con nombre, alcance y todas sus ejecuciones.
- Importación de Nmap (XML, grepable y normal) a un inventario persistente de activos, servicios y observaciones.
- Capturas web con gowitness, cada una ligada al servicio y la ejecución que la produjo.
- Exportación: inventario CSV/JSON, índice de capturas y ZIP por subred.
- Migración del historial anterior de `portal_datos/` a una auditoría «Importadas».
- Instalación automática de gowitness verificada por SHA-256.

**Queda para después:** descubrimiento de red (bloque 2), lanzar Nmap desde el portal (bloque 3), correlación y priorización con IA (bloque 5) y comprobación de credenciales (bloque 6).

**No se hará:** uso multiusuario, publicar el portal en red, explotar vulnerabilidades ni iniciar sesión en los servicios capturados.

La consola (`capturar`, `ver`) se mantiene como está; las auditorías son del portal.

## 0.2 Sistema de demostración

- **Entorno real:** el equipo Windows del auditor, conectado a la red de laboratorio o del cliente.
- **Sin red:** `ejemplos/inventario.xml` para el inventario y `python -m tests.integration_local` para capturas contra webs locales.
- Primera versión probada en Windows. Linux, en particular Kali, queda pendiente de una prueba real.

## 0.3 Alcance

Cada auditoría tiene una lista de reglas:

| Tipo | Ejemplo | Significado |
| --- | --- | --- |
| `incluir` | `10.10.0.0/16` | Red autorizada. También sirve para agrupar como hoy hacen los rangos. |
| `excluir` | `10.10.5.20/32`, motivo «impresora» | Nunca se contacta, aunque esté dentro de un rango incluido. |

Una IP queda en una de estas situaciones:

- **En alcance:** está en alguna regla `incluir` y en ninguna `excluir`.
- **Excluida:** está en alguna regla `excluir`. La exclusión siempre gana.
- **Fuera de alcance:** no está en ninguna regla `incluir`.

**Reglas que deben cumplir todos los módulos**

1. Importar nunca filtra. Todo lo que trae el Nmap se guarda, marcado con su situación, para no perder información.
2. **Solo se contacta lo que está en alcance.** Las capturas, y en el futuro el descubrimiento, los escaneos y las credenciales, comprueban el alcance justo antes de conectar, no solo al planificar.
3. Una auditoría sin reglas `incluir` no tiene nada en alcance: se puede importar y consultar, pero no lanzar conexiones. El portal pide definir el alcance.
4. Cambiar el alcance no borra datos; solo cambia qué se puede contactar a partir de ese momento.

> **Cambio respecto a hoy:** ahora mismo las IP que no están en ningún rango se capturan igualmente, agrupadas en `fuera_de_rango`. Con este contrato dejan de capturarse. Las ejecuciones migradas conservan sus capturas antiguas.

## 0.4 Etapas, estados y resultados

Cada cosa que se hace es una **ejecución** de un tipo. En la primera versión hay dos tipos:

| Tipo | Qué hace | ¿Conecta con objetivos? | Qué escribe |
| --- | --- | --- | --- |
| `importacion` | Lee archivos Nmap | No | Activos, servicios, observaciones y el Nmap original como evidencia |
| `captura` | Hace capturas de los servicios web en alcance de una importación | Sí, HTTP/HTTPS | Un resultado por URL y las imágenes como evidencia |

Tipos futuros: `descubrimiento` y `escaneo` (conectan, solo en alcance), `correlacion` (no conecta) y `credenciales` (conecta, con límites).

**Estados de una ejecución**

```text
preparada → en_cola → en_curso → completa
                   ↘ cancelada   ↘ deteniendo → interrumpida
                                 ↘ parcial | error | interrumpida
```

| Estado | Significado |
| --- | --- |
| `preparada` | Creada y revisable; todavía no ha hecho nada contra la red. |
| `en_cola` | Esperando a que termine la ejecución activa. Se ejecutan de una en una. |
| `en_curso` | Trabajando. |
| `deteniendo` | Se pidió parar; termina la subred actual. |
| `completa` | Terminó y todo salió bien. |
| `parcial` | Terminó, pero algún objetivo no tiene resultado. El resto es utilizable. |
| `error` | No pudo terminar; el motivo se guarda. |
| `cancelada` | Se canceló antes de empezar. |
| `interrumpida` | Se detuvo a mitad, a petición o porque se cerró el portal. No se relanza sola. |

Una importación pasa directamente de `preparada` a `completa`, o a `error` si el archivo no es válido.

**Resultado de cada URL en una captura:** `pendiente`, `capturada` o `sin_captura`, más el motivo del fallo cuando no hay imagen.
