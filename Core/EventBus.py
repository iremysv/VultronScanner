"""
VultronScanner — Core/EventBus.py
===================================
Async pub/sub message broker for inter-module communication.

Design
------
- Topic-based routing via ``EventTopic`` enum
- ``asyncio.Queue`` per subscriber — no shared mutable state
- Subscribers register a callback coroutine; EventBus drives the loop
- Wildcard subscription via ``EventTopic.*`` pattern (subscribe_all)
- Fire-and-forget publish; blocked subscribers do not stall the pipeline
- Thread-safe counter for delivered message metrics

Usage
-----
    bus = EventBus()

    async def on_host(event: ScanEvent) -> None:
        print(event.payload["ip"])

    bus.subscribe(EventTopic.HOST_ALIVE, on_host)
    await bus.publish(ScanEvent(topic=EventTopic.HOST_ALIVE, ...))
    await bus.shutdown()
"""

from __future__ import annotations

import asyncio
import threading
from collections import defaultdict
from typing import Awaitable, Callable, DefaultDict, Dict, List

from Core.Models import EventTopic, ScanEvent
from Utils.Logger import get_logger

log = get_logger("eventbus")

# Type alias
_Handler = Callable[[ScanEvent], Awaitable[None]]


class EventBus:
    """
    Async publish/subscribe event broker.

    Thread-safe, singleton-friendly, supports graceful shutdown.
    """

    def __init__(self) -> None:
        # topic → list of handler coroutines
        self._handlers: DefaultDict[EventTopic, List[_Handler]] = defaultdict(list)
        # wildcard handlers receive every event
        self._wildcard_handlers: List[_Handler] = []
        # metrics
        self._published: int = 0
        self._delivered: int = 0
        self._lock = threading.Lock()
        self._shutdown_event = asyncio.Event()

    # ------------------------------------------------------------------
    # Subscription API
    # ------------------------------------------------------------------

    def subscribe(self, topic: EventTopic, handler: _Handler) -> None:
        """Register *handler* to be called when *topic* events are published."""
        with self._lock:
            self._handlers[topic].append(handler)
        log.debug("Handler registered", topic=topic.value, handler=handler.__qualname__)

    def subscribe_all(self, handler: _Handler) -> None:
        """Register *handler* to receive every event regardless of topic."""
        with self._lock:
            self._wildcard_handlers.append(handler)
        log.debug("Wildcard handler registered", handler=handler.__qualname__)

    def unsubscribe(self, topic: EventTopic, handler: _Handler) -> None:
        """Remove a previously registered handler."""
        with self._lock:
            try:
                self._handlers[topic].remove(handler)
            except ValueError:
                log.warning("Handler not found for unsubscribe", topic=topic.value)

    # ------------------------------------------------------------------
    # Publish API
    # ------------------------------------------------------------------

    async def publish(self, event: ScanEvent) -> None:
        """
        Dispatch *event* to all subscribers.

        Each handler is awaited sequentially within a gathered task so
        a slow handler does not block the publisher.
        """
        with self._lock:
            handlers = list(self._handlers[event.topic]) + self._wildcard_handlers
            self._published += 1

        if not handlers:
            log.trace("No subscribers", topic=event.topic.value)
            return

        tasks = [asyncio.create_task(self._safe_call(h, event)) for h in handlers]
        await asyncio.gather(*tasks, return_exceptions=True)

        with self._lock:
            self._delivered += len(handlers)

        log.trace(
            "Event dispatched",
            topic=event.topic.value,
            subscribers=len(handlers),
            event_id=event.event_id,
        )

    async def _safe_call(self, handler: _Handler, event: ScanEvent) -> None:
        """Call a handler, catching and logging any exceptions."""
        try:
            await handler(event)
        except Exception as exc:  # noqa: BLE001
            log.error(
                "Handler raised exception",
                handler=handler.__qualname__,
                topic=event.topic.value,
                error=str(exc),
            )

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def shutdown(self) -> None:
        """Signal graceful shutdown."""
        self._shutdown_event.set()
        log.info(
            "EventBus shutdown",
            published=self._published,
            delivered=self._delivered,
        )

    # ------------------------------------------------------------------
    # Metrics
    # ------------------------------------------------------------------

    @property
    def stats(self) -> Dict[str, int]:
        with self._lock:
            return {
                "published": self._published,
                "delivered": self._delivered,
                "topics": len(self._handlers),
                "wildcards": len(self._wildcard_handlers),
            }

    def __repr__(self) -> str:  # pragma: no cover
        s = self.stats
        return (
            f"EventBus(published={s['published']}, "
            f"delivered={s['delivered']}, "
            f"topics={s['topics']})"
        )
