// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "service_map.h"

#include <set>
#include <string>

namespace ccf
{
  using WlId = uint8_t;
  using Whitelist = std::set<std::string>;
  // whitelists are sets of table names
  using Whitelists = ServiceMap<WlId, Whitelist>;

  enum WlIds : WlId
  {
    // tables members can read
    MEMBER_CAN_READ = 0,
    // tables members can propose changes to
    MEMBER_CAN_PROPOSE,
  };
}