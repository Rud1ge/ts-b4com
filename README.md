# ts-b4com

Repository for storing b4com terms of reference materials

## Тестовая топология сети

```markdown
┌──────┐      ┌───────┐      ┌──────────┐
│  TG  │ ───▶ │  DUT  │ ───▶ │ NEXTHOP1 │
└──────┘      └───────┘      └──────────┘
```

- **TG — Traffic Generator**
    - Настраивается интерфейс к **DUT**
    - Настраивается **маршрут по умолчанию через DUT** (gateway = `192.168.0.2`)

- **DUT — Device Under Test**
    - Настраивается интерфейс к **TG**
    - Настраивается интерфейс к **NEXTHOP**
    - Включается маршрутизация (**IP forwarding**)
    - Настраивается маршрут до **NEXTHOP**: `172.16.0.254/32 via 10.0.0.3`

- **NEXTHOP — End point**
    - Поднимается loopback адрес конечной точки: `172.16.0.254/32`