from dataclasses import dataclass
from electionguard.decryption import compute_decryption_share_for_selection
from electionguard.decryption_share import CiphertextDecryptionContest, CiphertextDecryptionSelection
from electionguard.group import ElementModP
from electionguard.key_ceremony import ElectionPartialKeyVerification, PublicKeySet, ElectionPartialKeyBackup
from electionguard.guardian import Guardian
from electionguard.serializable import Serializable
from electionguard.tally import CiphertextTallyContest
from electionguard.types import CONTEST_ID, GUARDIAN_ID, SELECTION_ID
from electionguard.utils import get_optional
from typing import Dict, Set, List, Optional, Literal, Type, Tuple
from .common import Context, ElectionStep, Key, Wrapper, Content
from .utils import pair_with_object_id, serialize, deserialize, deserialize_key

class TrusteeContext(Context):
    guardian: Guardian
    guardian_id: GUARDIAN_ID
    guardian_ids: Set[GUARDIAN_ID]

    def __init__(self, guardian_id: GUARDIAN_ID) -> None:
        self.guardian_id = guardian_id

class ProcessCreateElection(ElectionStep):
    order: int

    message_type = 'create_election'

    def process_message(self, message_type: Literal['create_election'], message: dict, context: TrusteeContext) -> Tuple[None, ElectionStep]:
        context.build_election(message)

        guardian_ids: List[GUARDIAN_ID] = [trustee['name'] for trustee in message['trustees']]
        context.guardian_ids = set(guardian_ids)
        order = guardian_ids.index(context.guardian_id)
        context.guardian = Guardian(context.guardian_id, order, context.number_of_guardians, context.quorum)

        return None, ProcessStartKeyCeremony()

class ProcessStartKeyCeremony(ElectionStep):
    message_type = 'start_key_ceremony'

    def process_message(self, message_type: Literal['start_key_ceremony'], _message: Content, context: TrusteeContext) -> Tuple[Content, ElectionStep]:
        return {'message_type': 'trustee_election_keys', 'content': serialize(context.guardian.share_public_keys())}, ProcessTrusteeElectionKeys()

@dataclass
class TrusteePartialKeys(Serializable):
    guardian_id: GUARDIAN_ID
    partial_keys: List[ElectionPartialKeyBackup]

class ProcessTrusteeElectionKeys(ElectionStep):
    message_type = 'trustee_election_keys'

    def process_message(self, message_type: Literal['trustee_election_keys'], message: Content, context: TrusteeContext) -> Tuple[Optional[Content], Optional[ElectionStep]]:
        content = deserialize(message['content'], PublicKeySet)
        if content.owner_id == context.guardian_id:
            return None, None

        context.guardian.save_guardian_public_keys(content)

        if context.guardian.all_public_keys_received():
            context.guardian.generate_election_partial_key_backups()

            return {
                'message_type': 'trustee_partial_election_keys',
                'content': serialize(TrusteePartialKeys(
                    guardian_id=context.guardian_id,
                    partial_keys=[
                        context.guardian.share_election_partial_key_backup(guardian_id)
                        for guardian_id in context.guardian_ids
                        if context.guardian_id != guardian_id
                    ]
                ))
            }, ProcessTrusteePartialElectionKeys()
        else:
            return None, None

@dataclass
class TrusteeVerification(Serializable):
    guardian_id: GUARDIAN_ID
    verifications: List[ElectionPartialKeyVerification]

class ProcessTrusteePartialElectionKeys(ElectionStep):
    message_type = 'trustee_partial_election_keys'

    def process_message(self, message_type: Literal['trustee_partial_election_keys'], message: Content, context: TrusteeContext) -> Tuple[Optional[Content], Tuple[ElectionStep]]:
        content = deserialize(message['content'], TrusteePartialKeys)
        if content.guardian_id == context.guardian_id:
            return None, None

        for partial_keys_backup in content.partial_keys:
            if partial_keys_backup.designated_id == context.guardian_id:
                context.guardian.save_election_partial_key_backup(partial_keys_backup)

        if context.guardian.all_election_partial_key_backups_received():

            # TODO: check that verifications are OK

            return {
                'message_type': 'trustee_verification',
                'content': serialize(TrusteeVerification(
                    guardian_id=context.guardian_id,
                    verifications=[
                        context.guardian.verify_election_partial_key_backup(guardian_id)
                        for guardian_id in context.guardian_ids
                        if context.guardian_id != guardian_id
                    ]
                ))
            }, ProcessTrusteeVerification()
        else:
            return None, None


class ProcessTrusteeVerification(ElectionStep):
    received_verifications: Set[GUARDIAN_ID]

    message_type = 'trustee_verification'

    def setup(self):
        self.received_verifications = set()

    def process_message(self, message_type: Literal['trustee_verification'], message: Content, context: TrusteeContext) -> Tuple[None, Optional[ElectionStep]]:
        content = deserialize(message['content'], TrusteeVerification)
        self.received_verifications.add(content.guardian_id)

        # TODO: everything should be ok
        if context.guardian_ids == self.received_verifications:
            return None, ProcessEndKeyCeremony()
        else:
            return None, None


class ProcessEndKeyCeremony(ElectionStep):
    message_type = 'end_key_ceremony'

    def process_message(self, message_type: Literal['end_key_ceremony'], message: Content, context: TrusteeContext) -> Tuple[None, ElectionStep]:
        joint_key = deserialize_key(message['content']['joint_key'])
        context.election_builder.set_public_key(get_optional(joint_key))
        context.election_metadata, context.election_context = get_optional(context.election_builder.build())
        # TODO: coefficient validation keys???
        # TODO: check joint key, without using private variables if possible
        #         serialize(elgamal_combine_public_keys(context.guardian._guardian_election_public_keys.values()))
        return None, ProcessTallyCast()

@dataclass
class TallyCast(Serializable):
    guardian_id: GUARDIAN_ID
    public_key: Key
    contests: Dict[CONTEST_ID, CiphertextDecryptionContest] 

class ProcessTallyCast(ElectionStep):
    message_type = 'tally_cast'

    def process_message(self, message_type: Literal['tally_cast'], message: Content, context: TrusteeContext) -> Content:
        contests: Dict[CONTEST_ID, CiphertextDecryptionContest] = {}

        tally_cast: Dict[CONTEST_ID, CiphertextTallyContest] = deserialize(message['content'], Dict[CONTEST_ID, CiphertextTallyContest])

        for contest in tally_cast.values():
            selections: Dict[SELECTION_ID, CiphertextDecryptionSelection] = dict(
              pair_with_object_id(
                  compute_decryption_share_for_selection(context.guardian, selection, context.election_context)
              )
              for (_, selection) in contest.tally_selections.items()
            )

            contests[contest.object_id] = CiphertextDecryptionContest(
                contest.object_id, context.guardian_id, contest.description_hash, selections
            )

        return {
            'content': serialize(TallyCast(
                guardian_id=context.guardian_id,
                public_key=context.guardian.share_election_public_key().key,
                contests=contests
            ))
        }


class Trustee(Wrapper[TrusteeContext]):
    starting_step = ProcessCreateElection

    def __init__(self, guardian_id: GUARDIAN_ID) -> None:
        super().__init__(TrusteeContext(guardian_id), self.starting_step())

    def is_key_ceremony_done(self) -> bool:
        return self.step.__class__ in [ProcessTallyCast]

    def is_tally_done(self) -> bool:
        return self.step.__class__ in [] # TODO: implement tally
