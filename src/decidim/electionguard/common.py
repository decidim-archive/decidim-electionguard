from dataclasses import dataclass
from electionguard.election import CiphertextElectionContext, ElectionDescription, InternalElectionDescription
from electionguard.election_builder import ElectionBuilder
from electionguard.group import ElementModP
from electionguard.serializable import Serializable
from typing import Generic, NewType, TypeVar, TypedDict, Type
from .utils import complete_election_description, InvalidElectionDescription
try:
    import cPickle as pickle
except:  # noqa: E722
    import pickle


class Context:
    election: ElectionDescription
    election_builder: ElectionBuilder
    election_metadata: InternalElectionDescription
    election_context: CiphertextElectionContext
    number_of_guardians: int
    quorum: int

    def build_election(self, election_creation: dict):
        self.election = ElectionDescription.from_json_object(complete_election_description(election_creation['description']))

        if not self.election.is_valid():
            raise InvalidElectionDescription()

        self.number_of_guardians = len(election_creation['trustees'])
        self.quorum = election_creation['scheme']['parameters']['quorum']
        self.election_builder = ElectionBuilder(self.number_of_guardians, self.quorum, self.election)



C = TypeVar('C', bound=Context)

@dataclass
class Content(TypedDict):
    content: object

class ElectionStep(Generic[C]):
    message_type: str

    def __init__(self) -> None:
        self.setup()

    def setup(self):
        pass

    def skip_message(self, message_type: str) -> bool:
        return self.message_type != message_type

    def process_message(self, message_type: str, message: Content, context: C) -> Content:
        raise NotImplementedError()


class Wrapper(Generic[C]):
    context: C
    step: ElectionStep[C]

    def __init__(self, context: C, step: ElectionStep[C]) -> None:
        self.context = context
        self.step = step

    def skip_message(self, message_type: str) -> bool:
        return self.step.skip_message(message_type)

    def process_message(self, message_type: str, message: Content) -> Content:
        if self.step.skip_message(message_type):
            return

        result, next_step = self.step.process_message(message_type, message, self.context)

        if next_step:
            self.step = next_step

        return result

    def is_fresh(self) -> bool:
        return isinstance(self.step, self.starting_step)

    def is_key_ceremony_done(self) -> bool:
        raise NotImplementedError

    def is_tally_done(self) -> bool:
        raise NotImplementedError

    def backup(self) -> str:
        return pickle.dumps(self)

    def restore(backup: str): # returns an instance of myself
        return pickle.loads(backup)
