from lxml.etree import ElementNamespaceClassLookup
from lxml.objectify import ObjectifyElementClassLookup, ElementMaker, ObjectifiedElement
from lxml import objectify
from .fvdl import FortifyObjectifiedDataElement

ExternalMetadataParser = objectify.makeparser(ns_clean=True,
                                              remove_blank_text=True,
                                              resolve_entities=False,
                                              strip_cdata=False)

ExternalMetadataElementNamespaceClassLookup = ElementNamespaceClassLookup(
    ObjectifyElementClassLookup())

class ExternalMetadataPackElement(FortifyObjectifiedDataElement):

    metadata_name_shortcut_cache = {}

    @property
    def namespace_map(self):
        # lxml is really dumb with xml using default namespaces.  You have to define a dummy namespace prefix to the
        # default namespace even though that prefix doesn't exist in the raw xml. Define a consistent map for all xpath
        return {'z':'xmlns://www.fortifysoftware.com/schema/externalMetadata'}

    # in goes a metadata name and out comes a list of shortcuts for that name
    def get_shortcuts_for_name(self, name):
        if name not in self.metadata_name_shortcut_cache:
            self.metadata_name_shortcut_cache[name] = self.xpath("./z:ExternalList[z:Name='%s']/z:Shortcut/text()" % name,
                          namespaces=self.namespace_map)

        return self.metadata_name_shortcut_cache[name]


EXTERNALMETADATA_NAMESPACE = ExternalMetadataElementNamespaceClassLookup.get_namespace("xmlns://www.fortifysoftware.com/schema/externalMetadata")

EXTERNALMETADATA_NAMESPACE['ExternalMetadataPack'] = ExternalMetadataPackElement

ExternalMetadataParser.set_element_class_lookup(
    ExternalMetadataElementNamespaceClassLookup)

ExternalMetadataPack = ElementMaker(
    annotate=False,
    namespace='xmlns://www.fortifysoftware.com/schema/externalMetadata',
    nsmap={
        None: 'xmlns://www.fortifysoftware.com/schema/externalMetadata'
    }
)
