import os.path
from abc import ABC, abstractmethod
from datetime import date
from enum import StrEnum
from typing import TypeVar, Iterable, Callable, Any
from xml.dom import minidom
from xml.dom.minidom import Text, Element, Document, Node

_K = TypeVar('_K')
_T = TypeVar('_T')

CopyrightYear = int | tuple[int, int]

_MINIMUM_YEAR = 1950
_MAXIMUM_YEAR = 2099

_FILE_ENCODING_UTF8 = 'utf-8'


def _require(x: _T | None) -> _T:
    if x is None:
        raise ValueError('missing mandatory value')
    if isinstance(x, str) and x.strip() == '':
        raise ValueError('mandatory value must not be blank')
    return x


def _direct_child_elements(root: Node, tag_name: str) -> list[Element]:
    out: list[Element] = []
    for child in root.childNodes:
        if isinstance(child, Element) and child.tagName == tag_name:
            out.append(child)
    return out


def _exactly_one_element(root: Node, tag_name: str) -> Element:
    elems = _direct_child_elements(root, tag_name)
    if len(elems) != 1:
        raise ValueError(f'exactly one "{tag_name}" element required, found {len(elems)}')
    return elems[0]


def _optional_element(root: Node, tag_name: str) -> Element | None:
    if root is None:
        return None
    elems = _direct_child_elements(root, tag_name)
    if len(elems) > 1:
        raise ValueError(f'at most one "{tag_name}" element required, found {len(elems)}')
    return elems[0] if len(elems) == 1 else None


def _all_elements(root: Node, tag_name: str) -> list[Element]:
    if root is None:
        return []
    return _direct_child_elements(root, tag_name)


def _at_least_one_element(root: Node, tag_name: str) -> list[Element]:
    elems = _all_elements(root, tag_name)
    if len(elems) == 0:
        raise ValueError(f'at least one "{tag_name}" element is required')
    return elems


def _parse_elements_indexed(elems: Iterable[Element], parser: Callable[[Element], _T],
                            key_getter: Callable[[_T], _K]) -> dict[_K, _T]:
    out: dict[_K, _T] = {}

    for elem in elems:
        parsed: _T = parser(elem)
        key: _K = key_getter(parsed)
        if key in out:
            raise ValueError(f'duplicate key: {key}')
        out[key] = parsed

    return out


def _optional_attribute(elem: Element, attr_name: str) -> str | None:
    if elem is None or not elem.hasAttribute(attr_name):
        return None

    s = elem.getAttribute(attr_name)
    if s.strip() == '':
        return None

    return s


def _mandatory_attribute(elem: Element, attr_name: str) -> str:
    s = _optional_attribute(elem, attr_name)
    if s is None:
        raise ValueError(f'mandatory attribute {attr_name} missing or blank: {elem}')

    return s


def _parse_year(s: str) -> int:
    year = int(s.strip())
    if year < _MINIMUM_YEAR or year > _MAXIMUM_YEAR:
        raise ValueError(f'Year {year} is out of range (must be between {_MINIMUM_YEAR} and {_MAXIMUM_YEAR})')
    return year


def _parse_years(s: str) -> list[int | tuple[int, int]]:
    out: list[int | tuple[int, int]] = []

    for interval in s.split(','):
        years = interval.split('-')
        if len(years) > 2:
            raise ValueError(f'invalid year interval format: {s}')
        elif len(years) == 1:
            out.append(_parse_year(years[0]))
        else:
            tmp = (_parse_year(years[0]), _parse_year(years[1]))
            if tmp[0] > tmp[1]:
                raise ValueError(f'wrong year order ({tmp[0]} > {tmp[1]}): {s}')
            elif tmp[0] == tmp[1]:
                out.append(tmp[0])
            else:
                out.append(tmp)

    out.sort(key=lambda x: x if isinstance(x, tuple) else (x, x))

    return out


def _get_text(node: Node) -> str | None:
    num_children = len(node.childNodes)
    if num_children == 0:
        return None
    elif num_children != 1:
        raise ValueError(f'unexpected number of child nodes ({num_children}) on {node}')

    maybe_text_node = next(iter(node.childNodes))
    if not isinstance(maybe_text_node, Text):
        raise ValueError(f'unexpected child nodes {maybe_text_node} found under {node}')

    return maybe_text_node.wholeText


def _optional_text(root: Node, tag_name: str) -> str | None:
    elem = _optional_element(root, tag_name)
    if elem is None:
        return None

    s = _get_text(elem)

    if s is None or s.strip() == '':
        return None

    return s


def _exactly_one_text(root: Node, tag_name: str) -> str:
    s = _optional_text(root, tag_name)
    if s is None:
        raise ValueError(f'missing mandatory text {tag_name} under {root}')

    return s


def _all_texts(root: Node, tag_name: str) -> list[str]:
    tmp = [_get_text(elem) for elem in _all_elements(root, tag_name)]
    return [x for x in tmp if x is not None and x.strip() != ""]


def _parse_date(s: str | None) -> date | None:
    if s is None:
        return None

    return date.fromisoformat(s)


def _all_of(*args: list[_T] | dict[Any, _T]) -> list[_T]:
    out: list[_T] = []
    for arg in args:
        if isinstance(arg, list):
            out.extend(arg)
        elif isinstance(arg, dict):
            for x in arg.values():
                out.append(x)
        else:
            raise ValueError(f'unhandled type for {arg}')
    return out


def _all_sbom_linkable(*args: list["SBOMLinkable"] | dict[Any, "SBOMLinkable"]) -> list["SBOMLinkable"]:
    # nasty workaround for Python 3.13 not inferring common inherited types from arguments and also not allowing
    # functions to be explicitly parameterized nor correctly interpreting optional coercion argument
    return _all_of(*args)


class SBOMLinkable(ABC):
    @abstractmethod
    def link_sbom(self, sbom: "SimpleSBOM"): ...


class LegalEntityType(StrEnum):
    PERSON = 'person'
    ORGANIZATION = 'organization'

    @classmethod
    def resolve(cls, encoding: str) -> "LegalEntityType":
        for v in cls.__members__.values():
            if v == encoding:
                return v
        raise ValueError(f'unknown encoding for LegalEntityType: {encoding}')


class LegalEntitySuccessorEvent(StrEnum):
    ACQUISITION = 'acquisition'
    """
    The original entity was acquired by another one.
    """

    RENAMING = 'renaming'
    """
    The entity was renamed but otherwise remained the same.
    """

    @classmethod
    def resolve(cls, encoding: str) -> "LegalEntitySuccessorEvent":
        for v in cls.__members__.values():
            if v == encoding:
                return v
        raise ValueError(f'unknown encoding for LegalEntitySuccessorEvent: {encoding}')


class LegalSource:
    def __init__(self, root: Element):
        self.checked: date = _parse_date(_mandatory_attribute(root, 'checked'))
        self.source: str = _require(_get_text(root))

    @classmethod
    def parse(cls, root: Element) -> "LegalSource":
        return cls(root)


class LegalEntitySuccessor:
    def __init__(self, root: Element):
        self.id: str = _exactly_one_text(root, 'id')
        self.event: LegalEntitySuccessorEvent = LegalEntitySuccessorEvent.resolve(_exactly_one_text(root, 'event'))
        self.date: date | None = _parse_date(_optional_attribute(root, 'check'))
        self.sources: list[LegalSource] = [
            LegalSource.parse(elem)
            for elem in _at_least_one_element(root, 'source')
        ]

    @classmethod
    def parse(cls, root: Element) -> "LegalEntitySuccessor":
        return cls(root)


class LegalEntityContactType(StrEnum):
    WEBSITE = 'website'
    EMAIL = 'email'

    @classmethod
    def resolve(cls, encoding: str) -> "LegalEntityContactType":
        for v in cls.__members__.values():
            if v == encoding:
                return v
        raise ValueError(f'unknown encoding for LegalEntityContactType: {encoding}')


class LegalEntityContact:
    def __init__(self, root: Element):
        self.type: LegalEntityContactType = LegalEntityContactType.resolve(_mandatory_attribute(root, 'type'))
        self.checked: date = _parse_date(_mandatory_attribute(root, 'checked'))
        self.contact: str = _require(_get_text(root))

    @classmethod
    def parse(cls, root: Element) -> "LegalEntityContact":
        return cls(root)


class LegalEntityAssociationType(StrEnum):
    ACQUIRED_BY = 'acquired-by'
    OWNS = 'owns'
    ALIAS = 'alias'

    @classmethod
    def resolve(cls, encoding: str) -> "LegalEntityAssociationType":
        for v in cls.__members__.values():
            if v == encoding:
                return v
        raise ValueError(f'unknown encoding for LegalEntityAssociationType: {encoding}')

    def get_verb(self):
        if self == self.ACQUIRED_BY:
            return 'has been acquired by'
        elif self == self.OWNS:
            return 'owns'
        elif self == self.ALIAS:
            return 'is an alias of'

        raise ValueError(f'missing verb to describe {self}')


class LegalEntityAssociation(SBOMLinkable):
    object: "LegalEntity"  # initialized in post-processing

    def __init__(self, root: Element, subject: "LegalEntity"):
        self.subject: "LegalEntity" = subject

        # ID is only temporary, users should access self.other after object links have been established in post-processing
        self.__object_id: str = _exactly_one_text(root, 'id')

        self.type: LegalEntityAssociationType = LegalEntityAssociationType.resolve(_exactly_one_text(root, 'type'))
        self.effective_from: date | None = _parse_date(_optional_text(root, 'from'))
        self.effective_until: date | None = _parse_date(_optional_text(root, 'until'))
        self.sources: list[LegalSource] = [
            LegalSource.parse(elem)
            for elem in _all_elements(root, 'source')
        ]

    def verb(self):
        return self.type.get_verb()

    def link_sbom(self, sbom: "SimpleSBOM"):
        self.object = sbom.require_legal_entity(self.__object_id)
        self.object.record_reverse_association(self)

    @classmethod
    def parse(cls, root: Element, subject: "LegalEntity") -> "LegalEntityAssociation":
        return cls(root, subject)


class LegalEntity(SBOMLinkable):
    def __init__(self, root: Element):
        self.id: str = _mandatory_attribute(root, 'id')
        self.name: str = _exactly_one_text(root, 'name')
        self.type: LegalEntityType = LegalEntityType.resolve(_exactly_one_text(root, 'type'))
        self.contacts: list[LegalEntityContact] = [
            LegalEntityContact.parse(elem)
            for elem in _all_elements(root, 'contact')
        ]
        self.associations: list[LegalEntityAssociation] = [
            LegalEntityAssociation.parse(elem, self)
            for elem in _all_elements(root, 'association')
        ]
        """
        forward associations (association subject)
        """

        self.reverse_associations: list[LegalEntityAssociation] = []  # filled in when being linked
        """
        reverse associations (mentioned as association object)
        """

        defunct_elem = _optional_element(root, 'defunct')
        self.defunct: bool = defunct_elem is not None
        self.successors: list[LegalEntitySuccessor] = [
            LegalEntitySuccessor.parse(elem)
            for elem in _all_elements(defunct_elem, 'successor')
        ]

    def record_reverse_association(self, reverse_association: LegalEntityAssociation):
        self.reverse_associations.append(reverse_association)

    def link_sbom(self, sbom: 'SimpleSBOM'):
        for association in self.associations:
            association.link_sbom(sbom)

    @classmethod
    def parse(cls, root: Element) -> "LegalEntity":
        return cls(root)


class LicenseStandard:
    def __init__(self, root: Element):
        self.variations: list[str] = _all_texts(root, 'variation')
        self.spdx: str = _mandatory_attribute(root, 'spdx')

    @classmethod
    def parse(cls, root: Element) -> "LicenseStandard":
        return cls(root)


class License:
    def __init__(self, root: Element, base_dir: str | None = None):
        self.id: str = _mandatory_attribute(root, 'id')

        copy_elem = _optional_element(root, 'copy')
        self.text: str | None = _optional_text(root, 'copy')
        self.file: str | None = _optional_attribute(copy_elem, 'file')
        if self.file is not None and base_dir is not None:
            with open(os.path.join(base_dir, self.file), 'r', encoding=_FILE_ENCODING_UTF8) as fh:
                self.text = fh.read()

        standard_elem = _optional_element(root, 'standard')
        self.standard: LicenseStandard | None = LicenseStandard.parse(
            standard_elem) if standard_elem is not None else None

    @classmethod
    def parse(cls, root: Element, base_dir: str | None = None) -> "License":
        return cls(root, base_dir)


class Copyright:
    def __init__(self, root: Element, sbom: "SimpleSBOM"):
        self.authors: list[LegalEntity] = [
            sbom.require_legal_entity(author_id)
            for author_id in _all_texts(root, 'author')
        ]

        self.combined_authors: str | None = _optional_text(root, 'combinedAuthors')
        """
        Original listing of authors to be preferred over individual authors if available.
        """

        self.original_remarks: list[str] = _all_texts(root, 'originalRemark')
        """
        Original full copyright remarks to be preferred over individual rendering if available.
        """

        license_id: str | None = _optional_attribute(root, 'license')
        self.license: License | None = sbom.require_license(license_id) if license_id is not None else None

        years_encoded = _optional_attribute(root, 'years')
        self.years: list[CopyrightYear] = _parse_years(years_encoded) if years_encoded is not None else []
        """
        Years/year intervals to be mentioned in copyright notice (usually range of years the listed authors have been active).
        Tuples are from/to date ranges (incl.). All years are sorted in ascending order but may repeat or overlap.
        """

    @classmethod
    def parse(cls, root: Element, sbom: "SimpleSBOM") -> "Copyright":
        return cls(root, sbom)


class TrademarkMark(StrEnum):
    REG = 'reg'
    TM = 'tm'

    def get_glyph(self) -> str:
        if self == self.REG:
            return '\u00ae'
        elif self == self.TM:
            return '\u2122'
        raise ValueError(f'{self} has no glyph defined')

    @classmethod
    def resolve(cls, encoding: str) -> "TrademarkMark|None":
        if encoding == 'none':
            return None

        for v in cls.__members__.values():
            if v == encoding:
                return v
        raise ValueError(f'unknown encoding for TrademarkMark: {encoding}')


class TrademarkName:
    def __init__(self, root: Element):
        self.name: str = _require(_get_text(root))
        self.mark: TrademarkMark | None = TrademarkMark.resolve(_mandatory_attribute(root, 'mark'))

        mark_first_use_only_encoded: str | None = _optional_attribute(root, 'markFirstUseOnly')
        self.mark_first_use_only: bool | None = mark_first_use_only_encoded.lower() == 'true' if mark_first_use_only_encoded is not None else None

    @classmethod
    def parse(cls, root: Element) -> "TrademarkName":
        return cls(root)


class TrademarkOwner:
    def __init__(self, root: Element, sbom: 'SimpleSBOM'):
        expiration_encoded: str | None = _optional_attribute(root, 'expiration')
        self.expiration: date = _parse_date(expiration_encoded)
        self.entity: LegalEntity = sbom.require_legal_entity(_require(_get_text(root)))

    @classmethod
    def parse(cls, root: Element, sbom: 'SimpleSBOM') -> "TrademarkOwner":
        return cls(root, sbom)


class Trademark:
    def __init__(self, root: Element, sbom: "SimpleSBOM"):
        self.names: list[TrademarkName] = [
            TrademarkName.parse(elem)
            for elem in _at_least_one_element(root, 'name')
        ]
        self.owners: list[TrademarkOwner] = [
            TrademarkOwner.parse(elem, sbom)
            for elem in _at_least_one_element(root, 'owner')
        ]
        self.display: str = _exactly_one_text(root, 'display')
        self.sources: list[LegalSource] = [
            LegalSource.parse(elem)
            for elem in _all_elements(root, 'source')
        ]

    @classmethod
    def parse(cls, root: Element, sbom: "SimpleSBOM") -> "Trademark":
        return cls(root, sbom)


class DependencyType(StrEnum):
    DRIVER = 'driver'
    FONT = 'font'
    LIBRARY = 'library'

    @classmethod
    def resolve(cls, encoding: str) -> "DependencyType":
        for v in cls.__members__.values():
            if v == encoding:
                return v
        raise ValueError(f'unknown encoding for DependencyType: {encoding}')


class DependencyMethod(StrEnum):
    STATIC = 'static'
    SEPARATE = 'separate'
    MIXED = 'mixed'
    PROVIDED = 'provided'

    @classmethod
    def resolve(cls, encoding: str) -> "DependencyMethod":
        for v in cls.__members__.values():
            if v == encoding:
                return v
        raise ValueError(f'unknown encoding for DependencyMethod: {encoding}')


class Patch:
    def __init__(self, root: Element, sbom: "SimpleSBOM"):
        self.sources: list[str] = _all_texts(root, 'source')
        self.description: str = _exactly_one_text(root, 'description')
        self.copyrights: list[Copyright] = [
            Copyright.parse(elem, sbom)
            for elem in _all_elements(root, 'copyright')
        ]

    @classmethod
    def parse(cls, root: Element, sbom: "SimpleSBOM") -> "Patch":
        return cls(root, sbom)


class Dependency(SBOMLinkable):
    def __init__(self, root: Element, sbom: "SimpleSBOM"):
        self.id: str = _mandatory_attribute(root, 'id')
        self.name: str = _exactly_one_text(root, 'name')
        self.version: str | None = _optional_text(root, 'version')
        self.websites: list[str] = _all_texts(root, 'website')
        self.sources: list[str] = _all_texts(root, 'source')
        self.locations: list[str] = _all_texts(root, 'location')
        self.type: DependencyType = DependencyType.resolve(_optional_text(root, 'type') or 'library')
        self.method: DependencyMethod = DependencyMethod.resolve(_exactly_one_text(root, 'method'))
        self.description: str | None = _optional_text(root, 'description')

        self.excerpt: str | None = _optional_text(root, 'excerpt')
        """
        If set, only a certain part of the overall dependency is used; "excerpt" explains what exactly.  
        """

        self.developer_remarks: list[str] = _all_texts(root, 'developerRemark')
        """
        General notes (nice to know) for developers working with the dependency.
        """

        self.activation_tags = _all_texts(_optional_element(root, 'activation'), 'tag')
        """
        If set, any of the given project-specific tags must be in effect for this conditional dependency to become part
        of the actual build. If none of the tags apply, this dependency is not part of the project.
        """

        self.patches: list[Patch] = [
            Patch.parse(elem, sbom)
            for elem in _all_elements(root, 'patch')
        ]

        self.copyrights: list[Copyright] = [
            Copyright.parse(elem, sbom)
            for elem in _all_elements(root, 'copyright')
        ]

        direct_encoded: str | None = _optional_attribute(root, 'direct')
        self.is_direct_dependency: bool | None = direct_encoded.strip().lower() == 'true' if direct_encoded is not None else None

        # transitive dependencies and usages (back-references) will be linked by post-processing; only collect IDs for now
        self.__dependency_ids: list[str] = _all_texts(root, 'dependency')
        self.dependencies: list[Dependency] = []
        self.usages: list[Dependency] = []

    def record_usage(self, other: "Dependency"):
        self.usages.append(other)

    def link_sbom(self, sbom: "SimpleSBOM"):
        self.dependencies = [
            sbom.require_dependency(dependency_id)
            for dependency_id in self.__dependency_ids
        ]

        for dependency in self.dependencies:
            dependency.record_usage(self)

    def is_active(self, active_tags: Iterable[str]) -> bool | None:
        required_tags_any = set(self.activation_tags)
        if len(required_tags_any) == 0:
            return None

        active_tags = set(active_tags)
        return not active_tags.isdisjoint(required_tags_any)

    @classmethod
    def parse(cls, root: Element, sbom: "SimpleSBOM") -> "Dependency":
        return cls(root, sbom)


class Product:
    def __init__(self, root: Element, sbom: "SimpleSBOM"):
        self.name: str = _exactly_one_text(root, 'name')
        self.version: str | None = _optional_text(root, 'version')
        self.description: str = _exactly_one_text(root, 'description')
        self.websites: list[str] = _all_texts(root, 'website')
        self.sources: list[str] = _all_texts(root, 'source')
        self.copyrights: list[Copyright] = [
            Copyright.parse(elem, sbom)
            for elem in _at_least_one_element(root, 'copyright')
        ]

    @classmethod
    def parse(cls, root: Element, sbom: "SimpleSBOM") -> "Product":
        return cls(root, sbom)


class SimpleSBOM:
    def __init__(self, root_node: Element, base_dir: str | None = None):
        self.licenses: dict[str, License] = _parse_elements_indexed(
            _at_least_one_element(_exactly_one_element(root_node, 'licenses'), 'license'),
            lambda elem: License.parse(elem, base_dir=base_dir),
            lambda x: x.id,
        )

        self.legal_entities: dict[str, LegalEntity] = _parse_elements_indexed(
            _at_least_one_element(_exactly_one_element(root_node, 'legalEntities'), 'legalEntity'),
            LegalEntity.parse,
            lambda x: x.id,
        )

        self.dependencies: dict[str, Dependency] = _parse_elements_indexed(
            _all_elements(_exactly_one_element(root_node, 'dependencies'), 'dependency'),
            lambda elem: Dependency.parse(elem, self),
            lambda x: x.id,
        )

        self.trademarks: list[Trademark] = [
            Trademark.parse(elem, self)
            for elem in _all_elements(_exactly_one_element(root_node, 'trademarks'), 'trademark')
        ]

        self.product = Product.parse(_exactly_one_element(root_node, 'product'), self)

        for obj in _all_sbom_linkable(self.dependencies, self.legal_entities):
            obj.link_sbom(self)

    def get_dependency(self, dependency_id: str) -> Dependency | None:
        return self.dependencies[dependency_id]

    def require_dependency(self, dependency_id: str) -> Dependency:
        x = self.get_dependency(dependency_id)
        if x is None:
            raise ValueError(f'missing dependency with ID "{dependency_id}"')
        return x

    def get_license(self, license_id: str) -> License | None:
        return self.licenses[license_id]

    def require_license(self, license_id: str) -> License:
        x = self.get_license(license_id)
        if x is None:
            raise ValueError(f'missing license with ID "{license_id}"')
        return x

    def get_legal_entity(self, entity_id: str) -> LegalEntity | None:
        return self.legal_entities[entity_id]

    def require_legal_entity(self, entity_id: str) -> LegalEntity:
        x = self.get_legal_entity(entity_id)
        if x is None:
            raise ValueError(f'missing legal entity with ID "{entity_id}"')
        return x

    @staticmethod
    def parse_root(root_node: Element, base_dir: str | None = None) -> "SimpleSBOM":
        return SimpleSBOM(root_node, base_dir=base_dir)

    @classmethod
    def parse_document(cls, doc: Document, base_dir: str | None = None) -> "SimpleSBOM":
        return cls.parse_root(_exactly_one_element(doc, 'sbom'), base_dir=base_dir)

    @classmethod
    def parse_file(cls, path: str) -> "SimpleSBOM":
        if not os.path.exists(path):
            raise ValueError(f'file does not exist: {path}')
        return cls.parse_document(minidom.parse(path), base_dir=os.path.dirname(path))

    @classmethod
    def parse_xml(cls, xml: str, base_dir: str | None = None) -> "SimpleSBOM":
        return cls.parse_document(minidom.parseString(xml), base_dir=base_dir)
