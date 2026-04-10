# 🥤 Straws: Chaos Engineering Roadmap (Clean Metadata Edition)

Este documento detalla el plan estratégico para restaurar las capacidades de **Ingeniería de Caos** de forma "limpia" (sin ensuciar el tráfico HTTP con cabeceras personalizadas).

## Objetivos
- Restaurar la funcionalidad de los botones de caos en el modal de diagnóstico de cada **Leaf**.
- Utilizar exclusivamente la cabecera estándar `Proxy-Authorization` para el paso de metadatos.
- Garantizar que el tráfico hacia el servidor destino sea idéntico al original (sin rastros de Straws).

---

## 🚀 Plan de Restauración "Clean"

### Mejora de Protocolo (Identificada)
Para evitar que cabeceras como `X-Straws-Chaos` lleguen al servidor destino y causen interferencias, consolidaremos todo en la cabecera de autenticación del proxy.

1.  **Transporte Único:** El ID de la ventana, el ID de la pestaña y el Modo de Caos viajarán en el campo `Username` de la cabecera `Proxy-Authorization`.
2.  **Limpieza Automática:** El motor Go procesará esta cabecera y la **eliminará** antes de reenviar la petición al destino.

---

### Fase 1: Upgrade del Motor Go
**Objetivo:** Procesar el nuevo formato de metadatos y aplicar el caos.
- **Modificación de `extractIdentity`:** Capacidad de extraer el tag `chaos:MODE`.
- **Implementación de Acciones:**
  - `latency`: Delay fijo (ej. 1s).
  - `jitter`: Delay variable (ej. 0-2s).
  - `drop`: Cierre de conexión.
  - `error`: Retorno de status 500.
- **Middleware de Limpieza:** Asegurar que `req.Header.Del("Proxy-Authorization")` se ejecute antes del proxy inverso.

### Fase 2: Sincronización de la Extensión
**Objetivo:** Adaptar la inyección de cabeceras al nuevo formato limpio.
- **Modificación de `setupLeafTagging`:**
  - Eliminar inyección de `X-Straws-Leaf` y `X-Straws-Chaos`.
  - Inyectar una única cabecera `Proxy-Authorization` con el payload consolidado:
    `win:WIN|tab:TAB|chaos:MODE:straws` (en Base64).

### Fase 3: Feedback Silencioso
- El motor Go informará a la extensión sobre el caos aplicado a través de su canal de logs nativo, manteniendo el Dashboard actualizado sin afectar el tráfico externo.

---

## 🛠️ Detalles del Protocolo (Clean)

| Elemento | Método Anterior (Dirty) | Método Nuevo (Clean) |
| :--- | :--- | :--- |
| **Identidad (Tab/Win)** | `X-Straws-Leaf` | `Proxy-Authorization` |
| **Comando de Caos** | `X-Straws-Chaos` | `Proxy-Authorization` |
| **Visibilidad en Destino** | **Sí** (Puede romper apps) | **No** (Transparente) |

---

> [!IMPORTANT]
> Este enfoque sigue los estándares de los proxies profesionales, donde la cabecera `Proxy-Authorization` es consumida por el "Hop" intermedio y nunca llega al servidor final.
