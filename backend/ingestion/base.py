from abc import ABC, abstractmethod
from typing import AsyncIterator, Optional, List
import asyncio
import logging

from ..schemas.normalized import RawEvent, EventBatch, EventSourceType, NormalizedEvent

logger = logging.getLogger(__name__)


class EventCollector(ABC):
    def __init__(self, collector_id: str, source_type: EventSourceType):
        self.collector_id = collector_id
        self.source_type = source_type
        self._running = False

    @abstractmethod
    async def start(self) -> None:
        raise NotImplementedError

    @abstractmethod
    async def stop(self) -> None:
        raise NotImplementedError

    @abstractmethod
    async def collect(self) -> AsyncIterator[EventBatch]:
        raise NotImplementedError

    def is_running(self) -> bool:
        return self._running


class EventParser(ABC):
    @abstractmethod
    def parse(self, raw_event: RawEvent) -> Optional[NormalizedEvent]:
        raise NotImplementedError

    @abstractmethod
    def can_parse(self, raw_event: RawEvent) -> bool:
        raise NotImplementedError


class IngestionPipeline:
    def __init__(self):
        self.collectors: List[EventCollector] = []
        self.parsers: List[EventParser] = []
        self._running = False
        self._tasks: List[asyncio.Task] = []

    def register_collector(self, collector: EventCollector) -> None:
        self.collectors.append(collector)

    def register_parser(self, parser: EventParser) -> None:
        self.parsers.insert(0, parser)

    def find_parser(self, raw_event: RawEvent) -> Optional[EventParser]:
        return next((parser for parser in self.parsers if parser.can_parse(raw_event)), None)

    async def start_all(self) -> None:
        self._running = True
        for collector in self.collectors:
            await collector.start()
            self._tasks.append(asyncio.create_task(self._process_collector(collector)))

    async def stop_all(self) -> None:
        self._running = False
        for collector in self.collectors:
            await collector.stop()
        for task in self._tasks:
            task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks.clear()

    async def _process_collector(self, collector: EventCollector) -> None:
        try:
            async for batch in collector.collect():
                for raw_event in batch.events:
                    await self._process_event(raw_event)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Collector %s failed", collector.collector_id)

    async def _process_event(self, raw_event: RawEvent) -> None:
        parser = self.find_parser(raw_event)
        if parser is None:
            logger.warning("No parser for %s from %s", raw_event.source_type, raw_event.source_name)
            return
        try:
            normalized = parser.parse(raw_event)
            if normalized:
                await self._store_normalized_event(normalized)
                await self._trigger_detection(normalized)
        except Exception:
            logger.exception("Error processing raw event from %s", raw_event.source_name)

    async def _store_normalized_event(self, event: NormalizedEvent) -> None:
        # Storage is deliberately not wired until normalized event persistence is implemented.
        pass

    async def _trigger_detection(self, event: NormalizedEvent) -> None:
        # Detection is deliberately not wired until a normalized event adapter exists.
        pass


pipeline = IngestionPipeline()
