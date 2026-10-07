// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "alembic/lib/Alembic/AbcCoreFactory/All.h"
#include "alembic/lib/Alembic/AbcCoreOgawa/All.h"
#include "alembic/lib/Alembic/AbcGeom/All.h"
#include "alembic/lib/Alembic/AbcMaterial/All.h"

#include "fuzzer_temp_file.h"

using Alembic::AbcCoreAbstract::PropertyHeader;
using Alembic::AbcCoreAbstract::PropertyType;
using Alembic::AbcCoreFactory::IFactory;
using Alembic::AbcGeom::C4fArraySamplePtr;
using Alembic::AbcGeom::IArchive;
using Alembic::AbcGeom::IC4fGeomParam;
using Alembic::AbcGeom::ICompoundProperty;
using Alembic::AbcGeom::ICurves;
using Alembic::AbcGeom::ICurvesSchema;
using Alembic::AbcGeom::IFaceSet;
using Alembic::AbcGeom::IFaceSetSchema;
using Alembic::AbcGeom::IGeomBaseSchema;
using Alembic::AbcGeom::IN3fGeomParam;
using Alembic::AbcGeom::index_t;
using Alembic::AbcGeom::Int32ArraySamplePtr;
using Alembic::AbcGeom::IObject;
using Alembic::AbcGeom::IPolyMesh;
using Alembic::AbcGeom::IPolyMeshSchema;
using Alembic::AbcGeom::ISubD;
using Alembic::AbcGeom::ISubDSchema;
using Alembic::AbcGeom::IV2fGeomParam;
using Alembic::AbcGeom::IXform;
using Alembic::AbcGeom::IXformSchema;
using Alembic::AbcGeom::M44d;
using Alembic::AbcGeom::M44f;
using Alembic::AbcGeom::N3fArraySamplePtr;
using Alembic::AbcGeom::ObjectHeader;
using Alembic::AbcGeom::P3fArraySamplePtr;
using Alembic::AbcGeom::UInt32ArraySamplePtr;
using Alembic::AbcGeom::V2fArraySamplePtr;
using Alembic::AbcMaterial::IMaterial;
using Alembic::AbcMaterial::IMaterialSchema;

template <typename T> void dumpAttributes(T const &schema) {

  const size_t meshPropertyCount = schema.getNumProperties();

  for (size_t p = 0; p < meshPropertyCount; p++) {
    const PropertyHeader &header = schema.getPropertyHeader(p);
    const PropertyType pType = header.getPropertyType();
    const std::string &name = header.getName();

    if (name == "P") {
      schema.getNumSamples();
    } else if (name == "uv" || name == "st") {
      schema.getUVsParam().getNumSamples();
    } else if (name == ".arbGeomParams") {
      // additional geometry elements (color sets, additional texture
      // coordinates)
      const ICompoundProperty geoParam = schema.getArbGeomParams();
      const size_t geoPropCount = geoParam.getNumProperties();

      for (size_t g = 0; g < geoPropCount; g++) {
        const PropertyHeader &headerGeo = geoParam.getPropertyHeader(g);
        const std::string &nameGeo = headerGeo.getName();
      }
    }
  }
}

void dumpPolyMesh(const IObject &node) {
  const ObjectHeader &header = node.getHeader();
  const IPolyMesh mesh(node.getParent(), header.getName());
  const IPolyMeshSchema &schema = mesh.getSchema();

  // Mesh properties
  dumpAttributes(schema);
}

void dumpSubD(const IObject &node) {
  const ObjectHeader &header = node.getHeader();
  const ISubD mesh(node.getParent(), header.getName());
  const ISubDSchema &schema = mesh.getSchema();

  dumpAttributes(schema);
  schema.getSubdivisionSchemeProperty();
  schema.getFaceVaryingInterpolateBoundaryProperty();
  schema.getFaceVaryingPropagateCornersProperty();
  schema.getInterpolateBoundaryProperty();
}

void dumpFaceSet(const IObject &node) {
  const ObjectHeader &header = node.getHeader();
  const IFaceSet faceSet(node.getParent(), header.getName());
  const IFaceSetSchema &schema = faceSet.getSchema();
  schema.getNumSamples();
}

void dumpCurves(const IObject &node) {
  const ObjectHeader &header = node.getHeader();
  const ICurves curves(node.getParent(), header.getName());
  const ICurvesSchema &schema = curves.getSchema();

  dumpAttributes(schema);
}

void dumpXform(const IObject &node) {
  const ObjectHeader &header = node.getHeader();
  const IXform xform(node.getParent(), header.getName());
  const IXformSchema &schema = xform.getSchema();

  schema.getNumSamples();
  schema.getNumOps();
}

void dumpMaterial(const IObject &node) {
  const ObjectHeader &header = node.getHeader();
  IMaterial material(node.getParent(), header.getName());
  IMaterialSchema &schema = material.getSchema();

  std::vector<std::string> targetNames;
  schema.getTargetNames(targetNames);

  for (const std::string &target : targetNames) {
    std::vector<std::string> shaderTypes;
    schema.getShaderTypesForTarget(target, shaderTypes);
    const size_t shaderTypeCount = shaderTypes.size();
    for (size_t s = 0; s < shaderTypeCount; s++) {

      ICompoundProperty parameters =
          schema.getShaderParameters(target, shaderTypes[s]);
      const size_t parameterCount = parameters.getNumProperties();
    }
  }
}

void dumpNodes(const IObject &node) {
  const ObjectHeader &header = node.getHeader();
  // Dump the general node information.
  header.getName();
  header.getFullName();
  header.getMetaData().serialize();

  // Dump the type specific information.
  if (Alembic::AbcGeom::IPolyMesh::matches(header)) {
    dumpPolyMesh(node);
  } else if (Alembic::AbcGeom::ISubD::matches(header)) {
    dumpSubD(node);
  } else if (Alembic::AbcGeom::IFaceSet::matches(header)) {
    dumpFaceSet(node);
  } else if (Alembic::AbcGeom::ICurves::matches(header)) {
    dumpCurves(node);
  } else if (Alembic::AbcGeom::IXform::matches(header)) {
    dumpXform(node);
  } else if (Alembic::AbcMaterial::IMaterial::matches(header)) {
    dumpMaterial(node);
  } else { // Miscellaneous nodes such as the root.
    ;
  }

  // Dump the child headers.
  const size_t childCount = node.getNumChildren();
  for (size_t i = 0; i < childCount; i++) {
    dumpNodes(node.getChild(i));
  }
}

void dumpInfo(const char *file) {
  // Load the Alembic archive and verify that it is valid.
  IFactory factory;
  IArchive archive = factory.getArchive(file);

  if (archive.valid()) {
    archive.getName();
    dumpNodes(archive.getTop());
  }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzerTemporaryFile tempFile(data, size);
  dumpInfo(tempFile.filename());

  return 0;
}
