import asyncio
import logging
from typing import AsyncIterator, List
from ..schemas.normalized import RawEvent, EventBatch, EventSourceType, NormalizedEvent
from .base import EventCollector, EventParser

logger = logging.getLogger(__name__)


class CloudEventCollector(EventCollector):
    def __init__(self, collector_id: str = "cloud-collector", source_type: EventSourceType = EventSourceType.CLOUD_AWS):
        super().__init__(collector_id, source_type)
        self._poll_interval = 30

    async def start(self):
        self._running = True
        logger.info("Cloud collector (%s) started; provider polling remains unconfigured.", self.source_type.value)

    async def stop(self):
        self._running = False
        logger.info("Cloud collector (%s) stopped.", self.source_type.value)

    async def collect(self) -> AsyncIterator[EventBatch]:
        while self._running:
            await asyncio.sleep(self._poll_interval)
            events = await self._fetch_cloud_events()
            if events:
                yield EventBatch(events=events, source_type=self.source_type, collector_id=self.collector_id)

    async def _fetch_cloud_events(self) -> List[RawEvent]:
        return []


class AWSEventCollector(CloudEventCollector):
    def __init__(self, collector_id: str = "aws-collector"):
        super().__init__(collector_id, EventSourceType.CLOUD_AWS)

    async def _fetch_cloud_events(self) -> List[RawEvent]:
        return []


class AzureEventCollector(CloudEventCollector):
    def __init__(self, collector_id: str = "azure-collector"):
        super().__init__(collector_id, EventSourceType.CLOUD_AZURE)

    async def _fetch_cloud_events(self) -> List[RawEvent]:
        return []


class GCPEventCollector(CloudEventCollector):
    def __init__(self, collector_id: str = "gcp-collector"):
        super().__init__(collector_id, EventSourceType.CLOUD_GCP)

    async def _fetch_cloud_events(self) -> List[RawEvent]:
        return []


class CloudEventParser(EventParser):
    def can_parse(self, raw_event: RawEvent) -> bool:
        return raw_event.source_type in (
            EventSourceType.CLOUD_AWS, EventSourceType.CLOUD_AZURE, EventSourceType.CLOUD_GCP
        )

    def parse(self, raw_event: RawEvent) -> Optional[NormalizedEvent]:
        # No parser is registered until provider-specific schemas are configured.
        return None
