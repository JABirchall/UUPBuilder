package probes

import "uupbuilder/internal/engine/isocontent"

// Compatibility aliases retain the historical probe receipt format while the
// parser and its corruption tests now live with the production engine.
type ISOExpectedFile = isocontent.ISOExpectedFile
type ISOExpectations = isocontent.ISOExpectations
type ISOInspection = isocontent.ISOInspection

var InspectISO = isocontent.InspectISO
var inspectEFIPE = isocontent.InspectEFIPE
var inspectEFIFAT = isocontent.InspectEFIFAT
var validateISOExpectations = isocontent.ValidateExpectations

const isoLimit int64 = 5 << 30
