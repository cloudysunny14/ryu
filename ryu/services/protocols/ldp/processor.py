import logging

from ryu.services.protocols.bgp.utils import circlist
from ryu.services.protocols.ldp.base import Activity
from ryu.services.protocols.ldp.base import add_ldp_error_metadata
from ryu.services.protocols.ldp.base import LDP_PROCESSOR_ERROR_CODE
from ryu.services.protocols.ldp.base import LDPSException
from ryu.services.protocols.bgp.utils.evtlet import EventletIOFactory

LOG = logging.getLogger('ldpserver.processor')

@add_ldp_error_metadata(code=LDP_PROCESSOR_ERROR_CODE, sub_code=1,
                        def_desc='Error occurred when processing bgp '
                        'destination.')
class BgpProcessorError(LDPSException):
    """Base exception related to all destination path processing errors.
    """
    pass

class LdpProcessor(Activity):
    """Worker that processes queued `Destination'.

    `Destination` that have updates related to its paths need to be
    (re)processed. Only one instance of this processor is enough for normal
    cases. If you want more control on which destinations get processed faster
    compared to other destinations, you can create several instance of this
    works to achieve the desired work flow.
    """
    # Max. number of destinations processed per cycle.
    MAX_DEST_PROCESSED_PER_CYCLE = 100

    #
    # DestQueue
    #
    # A circular list type in which objects are linked to each
    # other using the 'next_dest_to_process' and 'prev_dest_to_process'
    # attributes.
    #
    _DestQueue = circlist.CircularListType(
        next_attr_name='next_dest_to_process',
        prev_attr_name='prev_dest_to_process')

    def __init__(self, core_service, work_units_per_cycle=None):
        Activity.__init__(self)
        # Back pointer to core service instance that created this processor.
        self._core_service = core_service
        self._dest_queue = LdpProcessor._DestQueue()
        self._rtdest_queue = LdpProcessor._DestQueue()
        self.dest_que_evt = EventletIOFactory.create_custom_event()
        self.work_units_per_cycle =\
            work_units_per_cycle or LdpProcessor.MAX_DEST_PROCESSED_PER_CYCLE

    def _run(self, *args, **kwargs):
        # Sit in tight loop, getting destinations from the queue and processing
        # one at a time.
        while True:
            LOG.debug('Starting new processing run...')
            # We process all RT destination first so that we get a new RT
            # filter that apply for each peer
            self._process_rtdest()

            # We then process a batch of other destinations (we do not process
            # all destination here as we want to give change to other
            # greenthread to run)
            self._process_dest()

            if self._dest_queue.is_empty():
                # If we have no destinations queued for processing, we wait.
                self.dest_que_evt.clear()
                self.dest_que_evt.wait()
            else:
                self.pause(0)

    def _process_dest(self):
        dest_processed = 0
        LOG.debug('Processing destination...')
        while (dest_processed < self.work_units_per_cycle and
                not self._dest_queue.is_empty()):
            # We process the first destination in the queue.
            next_dest = self._dest_queue.pop_first()
            if next_dest:
                next_dest.process()
                dest_processed += 1

    def _process_rtdest(self):
        LOG.debug('Processing RT NLRI destination...')
        if self._rtdest_queue.is_empty():
            return
        else:
            processed_any = False
            while not self._rtdest_queue.is_empty():
                # We process the first destination in the queue.
                next_dest = self._rtdest_queue.pop_first()
                if next_dest:
                    next_dest.process()
                    processed_any = True

            if processed_any:
                # Since RT destination were updated we update RT filters
                self._core_service.update_rtfilters()

    def enqueue(self, destination):
        """Enqueues given destination for processing.

        Given instance should be a valid destination.
        """
        if not destination:
            raise BgpProcessorError('Invalid destination %s.' % destination)

        dest_queue = self._dest_queue
        # RtDest are queued in a separate queue
        if destination.route_family == RF_RTC_UC:
            dest_queue = self._rtdest_queue

        # We do not add given destination to the queue for processing if
        # it is already on the queue.
        if not dest_queue.is_on_list(destination):
            dest_queue.append(destination)

        # Wake-up processing thread if sleeping.
        self.dest_que_evt.set()


