(() => {
  'use strict';
  const SCHEMAS = {
    component_Label: {
      1: ["runs", "component_Run"],
    },
    component_Run: {
      1: ["text", "string"],
    },
    component_ResponseContext: {
      6: ["serviceTrackingParams", "component_ServiceTrackingParam"],
    },
    component_ServiceTrackingParam: {
      1: ["service", "int"],
      2: ["params", "component_Param"],
    },
    component_Param: {
      1: ["key", "string"],
      2: ["value", "string"],
    },
    response_browse_Browse: {
      1: ["responseContext", "component_ResponseContext"],
      9: ["content", "response_browse_Content"],
      10: ["onResponseReceivedAction", "response_browse_Content"],
    },
    response_browse_Content: {
      58173949: ["singleColumnResultsRenderer", "response_browse_SingleColumnResultsRenderer"],
      153515154: ["elementRenderer", "response_browse_ElementRenderer"],
      49399797: ["sectionListRenderer", "response_browse_SectionListRenderer"],
    },
    response_browse_SingleColumnResultsRenderer: {
      1: ["tabs", "response_browse_BrowseTabSupportedRenderer"],
    },
    response_browse_BrowseTabSupportedRenderer: {
      58174010: ["tabRenderer", "response_browse_TabRenderer"],
    },
    response_browse_TabRenderer: {
      1: ["endpoint", "response_browse_TabEndpoint"],
      3: ["selected", "bool"],
      4: ["content", "response_browse_Content"],
      11: ["tabIdentifier", "string"],
    },
    response_browse_TabEndpoint: {
      48687626: ["browseEndpoint", "response_browse_TabBrowseEndpoint"],
    },
    response_browse_TabBrowseEndpoint: {
      2: ["browseId", "string"],
    },
    response_browse_SectionListRenderer: {
      1: ["sectionListSupportedRenderers", "response_browse_SectionListSupportedRenderer"],
    },
    response_browse_SectionListSupportedRenderer: {
      50195462: ["itemSectionRenderer", "response_browse_ItemSectionRenderer"],
      51845067: ["shelfRenderer", "response_browse_ShelfRenderer"],
      221496734: ["musicDescriptionShelfRenderer", "response_browse_MusicDescriptionShelfRenderer"],
    },
    response_browse_ItemSectionRenderer: {
      1: ["richItemContents", "response_browse_RichItemContent"],
    },
    response_browse_RichItemContent: {
      153515154: ["videoWithContextRenderer", "response_browse_ElementRenderer"],
    },
    response_browse_ElementRenderer: {
      172660663: ["videoRendererContent", "response_browse_VideoRendererContent"],
    },
    response_browse_VideoRendererContent: {
      1: ["videoInfo", "response_browse_VideoInfo"],
      2: ["renderInfo", "response_browse_RenderInfo"],
    },
    response_browse_VideoInfo: {
      168777401: ["videoContext", "response_browse_VideoContext"],
    },
    response_browse_VideoContext: {
      5: ["videoContent", "response_browse_VideoContent"],
    },
    response_browse_VideoContent: {
      465160965: ["timedLyricsRender", "response_browse_TimedLyricsRender"],
    },
    response_browse_TimedLyricsRender: {
      4: ["timedLyricsContent", "response_browse_TimedLyricsContent"],
    },
    response_browse_TimedLyricsContent: {
      1: ["runs", "component_Run"],
      2: ["footerLabel", "string"],
    },
    response_browse_RenderInfo: {
      183314536: ["layoutRender", "response_browse_LayoutRender"],
    },
    response_browse_LayoutRender: {
      1: ["eml", "string"],
    },
    response_browse_ShelfRenderer: {
      5: ["richSectionContent", "response_browse_RichSectionContent"],
    },
    response_browse_RichSectionContent: {
      51431404: ["reelShelfRenderer", "response_browse_ReelShelfRenderer"],
    },
    response_browse_ReelShelfRenderer: {
      1: ["richItemContents", "response_browse_RichItemContent"],
    },
    response_browse_MusicDescriptionShelfRenderer: {
      3: ["description", "component_Label"],
      10: ["footer", "component_Label"],
    },
    response_next_Next: {
      7: ["content", "response_next_Content"],
      8: ["onResponseReceivedAction", "response_browse_Content"],
    },
    response_next_Content: {
      51779735: ["nextResult", "response_next_NextResult"],
    },
    response_next_NextResult: {
      1: ["content", "response_browse_Content"],
    },
    response_search_Search: {
      4: ["content", "response_browse_Content"],
      7: ["onResponseReceivedCommand", "response_search_OnResponseReceivedCommand"],
    },
    response_search_OnResponseReceivedCommand: {
      50195462: ["itemSectionRenderer", "response_browse_ItemSectionRenderer"],
      49399797: ["appendContinuationItemsAction", "response_browse_SectionListRenderer"],
    },
    response_shorts_Shorts: {
      2: ["entries", "response_shorts_Entry"],
    },
    response_shorts_Entry: {
      1: ["command", "response_shorts_Command"],
    },
    response_shorts_Command: {
      139608561: ["reelWatchEndpoint", "response_shorts_ReelWatchEndpoint"],
    },
    response_shorts_ReelWatchEndpoint: {
      8: ["overlay", "response_shorts_Overlay"],
      16: ["adClientParams", "response_shorts_AdClientParams"],
    },
    response_shorts_AdClientParams: {
      1: ["isAd", "bool"],
    },
    response_shorts_Overlay: {
      139970731: ["reelPlayerOverlayRenderer", "response_shorts_ReelPlayerOverlayRenderer"],
    },
    response_shorts_ReelPlayerOverlayRenderer: {
      12: ["style", "int"],
    },
    response_guide_Guide: {
      4: ["labelItems", "response_guide_Item"],
      6: ["iconItems", "response_guide_Item"],
    },
    response_guide_Item: {
      117866661: ["guideSectionRenderer", "response_guide_GuideSectionRenderer"],
      123267149: ["mobileTopbarRenderer", "response_guide_MobileTopbarRenderer"],
    },
    response_guide_MobileTopbarRenderer: {
      4: ["buttons", "response_guide_Button"],
    },
    response_guide_Button: {
      65153809: ["buttonRenderer", "response_guide_ButtonRenderer"],
      322055134: ["topbarButtonRenderer", "response_guide_TopbarButtonRenderer"],
    },
    response_guide_TopbarButtonRenderer: {
      1: ["button", "response_guide_Button"],
    },
    response_guide_ButtonRenderer: {
      8: ["icon", "response_guide_Icon"],
    },
    response_guide_Icon: {
      1: ["iconType", "int"],
    },
    response_guide_GuideSectionRenderer: {
      1: ["rendererItems", "response_guide_RendererItem"],
    },
    response_guide_RendererItem: {
      318370163: ["iconRender", "response_guide_guideEntryRenderer"],
      117501096: ["labelRender", "response_guide_guideEntryRenderer"],
    },
    response_guide_guideEntryRenderer: {
      1: ["browseId", "string"],
      5: ["icon", "response_guide_Icon"],
    },
    response_player_Player: {
      7: ["adPlacements", "response_player_AdPlacement"],
      2: ["playabilityStatus", "response_player_PlayabilityStatus"],
      9: ["playbackTracking", "response_player_PlaybackTracking"],
      10: ["captions", "response_player_Captions"],
      68: ["adSlots", "response_player_AdSlot"],
    },
    response_player_AdPlacement: {
      84813246: ["adPlacementRenderer", "response_player_AdPlacementRenderer"],
    },
    response_player_AdPlacementRenderer: {
      4: ["params", "string"],
    },
    response_player_PlayabilityStatus: {
      21: ["pictureInPictureRender", "response_player_PictureInPictureSupportedRenderer"],
      11: ["backgroundPlayerRender", "response_player_BackgroundSupportedRenderer"],
    },
    response_player_PictureInPictureSupportedRenderer: {
      151635310: ["pictureInPictureAbility", "response_player_PictureInPictureAbility"],
    },
    response_player_BackgroundSupportedRenderer: {
      64657230: ["backgroundAbility", "response_player_BackgroundAbility"],
    },
    response_player_PictureInPictureAbility: {
      1: ["active", "bool"],
      4: ["f4", "int"],
      6: ["f6", "int"],
      8: ["f8", "int"],
    },
    response_player_BackgroundAbility: {
      1: ["active", "bool"],
    },
    response_player_PlaybackTracking: {
      1: ["videostatsPlaybackUrl", "response_player_Tracking"],
      2: ["videostatsDelayplayUrl", "response_player_Tracking"],
      3: ["videostatsWatchtimeUrl", "response_player_Tracking"],
      4: ["ptrackingUrl", "response_player_Tracking"],
      5: ["qoeUrl", "response_player_Tracking"],
      13: ["atrUrl", "response_player_Tracking"],
      15: ["videostatsEngageUrl", "response_player_Tracking"],
      18: ["pageadViewthroughconversion", "response_player_Tracking"],
    },
    response_player_Tracking: {
      1: ["baseUrl", "string"],
    },
    response_player_Captions: {
      51621377: ["playerCaptionsTrackListRenderer", "response_player_PlayerCaptionsTrackListRenderer"],
    },
    response_player_PlayerCaptionsTrackListRenderer: {
      1: ["captionTracks", "response_player_CaptionTrack"],
      2: ["audioTracks", "response_player_AudioTrack"],
      3: ["translationLanguages", "response_player_TranslationLanguage"],
      4: ["defaultAudioTrackIndex", "int"],
      6: ["defaultCaptionTrackIndex", "int"],
    },
    response_player_CaptionTrack: {
      1: ["baseUrl", "string"],
      2: ["name", "component_Label"],
      3: ["vssId", "string"],
      4: ["languageCode", "string"],
      5: ["kind", "string"],
      6: ["rtl", "bool"],
      7: ["isTranslatable", "bool"],
    },
    response_player_AudioTrack: {
      2: ["captionTrackIndices", "int"],
      3: ["defaultCaptionTrackIndex", "int"],
      4: ["forcedCaptionTrackIndex", "int"],
      5: ["visibility", "int"],
      6: ["hasDefaultTrack", "bool"],
      7: ["hasForcedTrack", "bool"],
      8: ["audioTrackId", "string"],
      11: ["captionsInitialState", "int"],
    },
    response_player_TranslationLanguage: {
      1: ["languageCode", "string"],
      2: ["languageName", "component_Label"],
    },
    response_player_AdSlot: {
      424701016: ["render", "response_player_AdSlot_Render"],
    },
    response_player_AdSlot_Render: {
    },
    response_setting_Setting: {
      6: ["settingItems", "response_setting_SettingItem"],
      7: ["CollectionItems", "response_setting_SettingItem"],
    },
    response_setting_SettingItem: {
      88478200: ["backgroundPlayBackSettingRenderer", "response_setting_BackgroundPlayBackSettingRenderer"],
      66930374: ["settingCategoryCollectionRenderer", "response_setting_SettingCategoryCollectionRenderer"],
    },
    response_setting_BackgroundPlayBackSettingRenderer: {
      1: ["name", "component_Label"],
      2: ["backgroundPlayback", "bool"],
      3: ["download", "bool"],
      5: ["trackingParams", "bytes"],
      9: ["downloadQualitySelection", "bool"],
      10: ["smartDownload", "bool"],
      14: ["icon", "response_setting_Icon"],
    },
    response_setting_SettingCategoryCollectionRenderer: {
      2: ["name", "component_Label"],
      3: ["subSettings", "response_setting_SubSetting"],
      4: ["categoryId", "int"],
      5: ["icon", "response_setting_Icon"],
    },
    response_setting_Icon: {
      1: ["iconType", "int"],
    },
    response_setting_SubSetting: {
      61331416: ["settingBooleanRenderer", "response_setting_SettingBooleanRenderer"],
    },
    response_setting_SettingBooleanRenderer: {
      2: ["title", "component_Label"],
      3: ["description", "component_Label"],
      5: ["enableServiceEndpoint", "response_setting_ServiceEndpoint"],
      6: ["disableServiceEndpoint", "response_setting_ServiceEndpoint"],
      15: ["itemId", "int"],
    },
    response_setting_ServiceEndpoint: {
      81212182: ["setClientSettingEndpoint", "response_setting_SetClientSettingEndpoint"],
    },
    response_setting_SetClientSettingEndpoint: {
      1: ["settingData", "response_setting_SettingData"],
    },
    response_setting_SettingData: {
      1: ["clientSettingEnum", "response_setting_ClientSettingEnum"],
      3: ["boolValue", "bool"],
    },
    response_setting_ClientSettingEnum: {
      1: ["item", "int"],
    },
    response_watch_Watch: {
      1: ["contents", "response_watch_Content"],
    },
    response_watch_Content: {
      2: ["player", "response_player_Player"],
      3: ["next", "response_next_Next"],
    },
  };


  const ROUTES = Object.freeze({
    browse: 'response_browse_Browse',
    next: 'response_next_Next',
    player: 'response_player_Player',
    search: 'response_search_Search',
    'reel/reel_watch_sequence': 'response_shorts_Shorts',
    get_watch: 'response_watch_Watch',
    guide: 'response_guide_Guide',
    'account/get_setting': 'response_setting_Setting',
  });
  const MAX_BODY = 16 * 1024 * 1024;
  const MAX_FIELDS = 200000;
  const MAX_DEPTH = 64;


  function bytes(value) {
    if (value instanceof Uint8Array) return value;
    if (value instanceof ArrayBuffer) return new Uint8Array(value);
    if (ArrayBuffer.isView(value)) return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
    throw new Error('Expected a binary body');
  }
  function readVarint(data, cursor, numeric = true) {
    let value = 0;
    let factor = 1;
    for (let count = 0; count < 10; count++) {
      if (cursor.pos >= data.length) throw new Error('Truncated varint');
      const byte = data[cursor.pos++];
      if (count === 9 && byte > 1) throw new Error('Invalid 64-bit varint');
      if (numeric) {
        value += (byte & 127) * factor;
        if (!Number.isSafeInteger(value)) throw new Error('Integer out of range');
      }
      if (!(byte & 128)) return value;
      factor *= 128;
    }
    throw new Error('Invalid varint');
  }

  function varint(value) {
    if (!Number.isSafeInteger(value) || value < 0) throw new Error('Invalid unsigned integer');
    const result = [];
    do {
      const low = value % 128;
      value = Math.floor(value / 128);
      result.push(low + (value ? 128 : 0));
    } while (value);
    return new Uint8Array(result);
  }

  function concat(parts) {
    let size = 0;
    for (const part of parts) size += part.length;
    if (size > MAX_BODY) throw new Error('Encoded body exceeds limit');
    const result = new Uint8Array(size);
    let offset = 0;
    for (const part of parts) { result.set(part, offset); offset += part.length; }
    return result;
  }
  function decode(input, type, depth = 0, budget = { fields: 0 }) {
    const data = bytes(input);
    if (data.length > MAX_BODY || depth > MAX_DEPTH) throw new Error('Protobuf limit exceeded');
    const schema = SCHEMAS[type];
    if (!schema) throw new Error('Unknown schema: ' + type);
    const node = { type, fields: [] };
    const cursor = { pos: 0 };
    while (cursor.pos < data.length) {
      if (++budget.fields > MAX_FIELDS) throw new Error('Too many protobuf fields');
      const start = cursor.pos;
      const tag = readVarint(data, cursor);
      const number = Math.floor(tag / 8);
      const wire = tag % 8;
      if (!number || number > 536870911) throw new Error('Invalid field number');
      let begin = cursor.pos;
      if (wire === 0) readVarint(data, cursor, false);
      else if (wire === 1) cursor.pos += 8;
      else if (wire === 5) cursor.pos += 4;
      else if (wire === 2) {
        const length = readVarint(data, cursor);
        begin = cursor.pos;
        cursor.pos += length;
      } else throw new Error('Unsupported wire type');
      if (cursor.pos > data.length) throw new Error('Truncated protobuf field');
      const field = { number, wire, raw: data.subarray(start, cursor.pos), data: data.subarray(begin, cursor.pos) };
      const definition = schema[number];
      if (definition && SCHEMAS[definition[1]]) {
        if (wire !== 2) throw new Error('Message wire type changed');
        field.child = decode(field.data, definition[1], depth + 1, budget);
      }
      node.fields.push(field);
    }
    return node;
  }

  function encode(node) {
    return concat(node.fields.map(field => {
      if (!field.child && field.raw) return field.raw;
      const value = field.child ? encode(field.child) : field.data;
      if (field.child && field.raw && same(value, field.data)) return field.raw;
      const tag = varint(field.number * 8 + field.wire);
      return field.wire === 2 ? concat([tag, varint(value.length), value]) : concat([tag, value]);
    }));
  }

  function all(node, number) { return node.fields.filter(field => field.number === number); }
  function child(node, number) { return all(node, number).find(field => field.child)?.child; }
  function integer(node, number, fallback = 0) {
    const field = all(node, number).find(item => item.wire === 0);
    return field ? readVarint(field.data, { pos: 0 }) : fallback;
  }
  function text(node, number) {
    const field = all(node, number).find(item => item.wire === 2 && !item.child);
    if (!field) return '';
    let encoded = '';
    for (const byte of field.data) encoded += '%' + byte.toString(16).padStart(2, '0');
    return decodeURIComponent(encoded);
  }
  function utf8(value) {
    const encoded = encodeURIComponent(value);
    const result = [];
    for (let i = 0; i < encoded.length; i++) {
      if (encoded[i] === '%') { result.push(parseInt(encoded.slice(i + 1, i + 3), 16)); i += 2; }
      else result.push(encoded.charCodeAt(i));
    }
    return new Uint8Array(result);
  }
  function drop(node, number) { node.fields = node.fields.filter(field => field.number !== number); }
  function set(node, number, value, kind = 'int') {
    drop(node, number);
    if (kind === 'message') node.fields.push({ number, wire: 2, child: value });
    else node.fields.push({ number, wire: kind === 'string' || kind === 'bytes' ? 2 : 0,
      data: kind === 'string' ? utf8(value) : kind === 'bytes' ? value : varint(Number(value)) });
  }
  function make(type) { return { type, fields: [] }; }
  function add(node, number, value) { node.fields.push({ number, wire: 2, child: value }); }
  function walk(node, visit) {
    visit(node);
    for (const field of node.fields) if (field.child) walk(field.child, visit);
  }
  function hasAscii(data, value) {
    outer: for (let i = 0; i <= data.length - value.length; i++) {
      for (let j = 0; j < value.length; j++) if (data[i + j] !== value.charCodeAt(j)) continue outer;
      return true;
    }
    return false;
  }


  function adUrl(value) {
    return /^https?:\/\/(?:[a-z0-9-]+\.)*(?:doubleclick\.net|googleadservices\.com)\/|^https?:\/\/(?:www|s)\.youtube\.com\/pagead(?:\/|\?)/i.test(value);
  }
  function rawStrings(data, path) {
    let cursor = { pos: 0 };
    for (let count = 0; cursor.pos < data.length && count < 1024; count++) {
      const tag = readVarint(data, cursor);
      const number = Math.floor(tag / 8), wire = tag % 8;
      if (!number) return false;
      if (wire === 0) readVarint(data, cursor, false);
      else if (wire === 1) cursor.pos += 8;
      else if (wire === 5) cursor.pos += 4;
      else if (wire === 2) {
        const length = readVarint(data, cursor), start = cursor.pos;
        cursor.pos += length;
        if (cursor.pos > data.length) return false;
        if (number === path[0]) {
          const value = data.subarray(start, cursor.pos);
          if (path.length === 1) {
            if (value.length > 4096) continue;
            let s = '';
            for (const b of value) { if (b > 127) { s = ''; break; } s += String.fromCharCode(b); }
            if (adUrl(s)) return true;
          } else if (rawStrings(value, path.slice(1))) return true;
        }
      } else return false;
      if (cursor.pos > data.length) return false;
    }
    return false;
  }
  const AD_PATHS = Object.freeze({
    454362329: [[8,4,2]], 224457493: [[2,3]], 461080918: [[7,4,2]],
    472329933: [[7,4,2]], 478840678: [[7,4,2]], 224590612: [[2,3],[2,9]],
    394770629: [[8,4,2]], 491441836: [[8,4,2]], 456430508: [[7,4,2]],
  });
  function hiddenLayout(value) {
    const layout = value.split('|')[0];
    return /^(?:.*_)?(?:shorts_shelf|inline_shorts|shorts_grid|shorts_video_cell|shorts_video|reel_shelf|horizontal_gaming_shelf|mini_game_card)(?:_[a-z0-9_]+)?\.eml(?:-fe)?$/.test(layout);
  }
  const HIDDEN_LAYOUTS = ['shorts_shelf', 'inline_shorts', 'shorts_grid', 'shorts_video_cell', 'shorts_video', 'reel_shelf', 'horizontal_gaming_shelf', 'mini_game_card'];
  function rawMarker(data, markers) {
    if (data.length > 262144) return false;
    let token = '';
    for (let i = 0; i <= data.length; i++) {
      const b = data[i];
      if ((b >= 48 && b <= 57) || (b >= 65 && b <= 90) || (b >= 97 && b <= 122) || b === 95 || b === 46 || b === 45 || b === 124) {
        if (token.length < 256) token += String.fromCharCode(b);
        else token = '!';
      } else {
        if (markers.includes(token) || (markers === HIDDEN_LAYOUTS && hiddenLayout(token))) return true;
        token = '';
      }
    }
    return false;
  }
  function hiddenElement(item) {
    let blocked = false;
    walk(item, node => {
      if (node.type === 'response_browse_LayoutRender' && hiddenLayout(text(node, 1))) blocked = true;
      if (node.type === 'response_browse_ElementRenderer' || node.type === 'response_browse_VideoRendererContent' || node.type === 'response_browse_VideoContent') {
        for (const field of node.fields) {
          if (!field.child && field.wire === 2 && !SCHEMAS[node.type][field.number] && rawMarker(field.data, HIDDEN_LAYOUTS)) blocked = true;
        }
      }
    });
    return blocked;
  }
  const GUIDE_TARGETS = [
    'FEshorts', 'FEmini_app_destination',
    'yt_outline_gaming', 'yt_outline_experimental_gaming',
    'yt_outline_tic_tac_toe', 'yt_outline_experimental_playables',
    'Gaming', 'Playables', '游戏', '游戏大本营', '遊戲', '遊戲大本營', '遊戲專區',
  ].map(utf8);
  function guideEvidence(data, depth = 0, budget = { count: 0 }) {
    if (!data.length || data.length > 262144 || depth > 6 || ++budget.count > 2048) return false;
    if (GUIDE_TARGETS.some(target => same(data, target))) return true;
    const cursor = { pos: 0 };
    try {
      while (cursor.pos < data.length && ++budget.count <= 2048) {
        const tag = readVarint(data, cursor);
        const wire = tag % 8;
        if (Math.floor(tag / 8) === 0) return false;
        if (wire === 0) readVarint(data, cursor, false);
        else if (wire === 1) cursor.pos += 8;
        else if (wire === 5) cursor.pos += 4;
        else if (wire === 2) {
          const length = readVarint(data, cursor), start = cursor.pos;
          cursor.pos += length;
          if (cursor.pos > data.length) return false;
          if (guideEvidence(data.subarray(start, cursor.pos), depth + 1, budget)) return true;
        } else return false;
        if (cursor.pos > data.length) return false;
      }
    } catch (_) {}
    return false;
  }
  const GAME_ICONS = new Set([120,354,553,627,1055,1078,1196,1207]);
  const MENU_LAYOUTS = ['list_item.e', 'list_item.eml', 'list_item.eml-fe'];
  const MENU_ICONS = [
    'yt_outline_gaming', 'yt_outline_experimental_gaming',
    'yt_outline_tic_tac_toe', 'yt_outline_experimental_playables',
    'FEmini_app_destination',
  ].map(utf8);
  function menuEvidence(data, targets, depth = 0, budget = { count: 0 }) {
    if (!data.length || data.length > 262144 || depth > 8 || ++budget.count > 4096) return false;
    if (targets.some(target => same(data, target))) return true;
    const cursor = { pos: 0 };
    try {
      while (cursor.pos < data.length && ++budget.count <= 4096) {
        const tag = readVarint(data, cursor), wire = tag % 8;
        if (!Math.floor(tag / 8)) return false;
        if (wire === 0) readVarint(data, cursor, false);
        else if (wire === 1) cursor.pos += 8;
        else if (wire === 5) cursor.pos += 4;
        else if (wire === 2) {
          const length = readVarint(data, cursor), start = cursor.pos;
          cursor.pos += length;
          if (cursor.pos > data.length) return false;
          if (menuEvidence(data.subarray(start, cursor.pos), targets, depth + 1, budget)) return true;
        } else return false;
        if (cursor.pos > data.length) return false;
      }
    } catch (_) {}
    return false;
  }
  const PLAYABLE_TAB_IDS = ['FEmini_app_destination'];
  const PLAYABLE_TAB_LABELS = ['Playables', '游戏大本营', '遊戲大本營', '遊戲角落'].map(utf8);
  const MORE_TAB_LABELS = ['More', '更多'].map(utf8);
  const MENU_LABELS = ['Gaming','游戏','遊戲','Playables','游戏大本营','遊戲大本營','遊戲角落'].map(utf8);
  function tabEvidence(tab, markers) {
    return tab.fields.some(field => !field.child && field.number !== 4 && field.wire === 2 && menuEvidence(field.data, markers));
  }
  function tabId(tab) {
    const endpoint = child(tab, 1);
    const browse = endpoint && child(endpoint, 48687626);
    return browse ? text(browse, 2) : '';
  }
  function isPlayableTab(tab) {
    return PLAYABLE_TAB_IDS.includes(tabId(tab)) || PLAYABLE_TAB_IDS.includes(text(tab, 11)) || tabEvidence(tab, PLAYABLE_TAB_LABELS);
  }
  function isMoreTab(tab) {
    return tabEvidence(tab, MORE_TAB_LABELS);
  }
  function filterHomeTabs(node) {
    walk(node, current => {
      if (current.type !== 'response_browse_SingleColumnResultsRenderer') return;
      const tabs = all(current, 1).map(field => field.child && child(field.child, 58174010)).filter(Boolean);
      if (!tabs.some(tab => ['FEwhat_to_watch','FEsubscriptions'].includes(tabId(tab)) || ['FEwhat_to_watch','FEsubscriptions'].includes(text(tab, 11)))) return;
      current.fields = current.fields.filter(field => {
        if (field.number !== 1 || !field.child) return true;
        const tab = child(field.child, 58174010);
        return !tab || integer(tab, 3) === 1 || !isPlayableTab(tab);
      });
      for (const tab of tabs) {
        if (integer(tab, 3) === 1 && isMoreTab(tab)) {
          const content = child(tab, 4);
          if (content) filterMoreMenu(content);
        }
      }
    });
  }
  function filterMoreMenu(node) {
    walk(node, current => {
      for (const field of current.fields) {
        if (field.child || field.wire !== 2 || !field.data.length) continue;
        const updated = pruneMenuBytes(field.data);
        if (updated !== field.data) {
          field.data = updated;
          delete field.raw;
        }
      }
    });
  }
  function parseMenuBytes(data) {
    const cursor = {pos:0}, fields = [];
    while (cursor.pos < data.length && fields.length < 1024) {
      const start=cursor.pos, tag=readVarint(data,cursor), number=Math.floor(tag/8), wire=tag%8;
      if (!number || number > 536870911) throw Error('Invalid menu field');
      let begin=cursor.pos;
      if (wire === 0) readVarint(data,cursor,false);
      else if (wire === 1) cursor.pos+=8;
      else if (wire === 5) cursor.pos+=4;
      else if (wire === 2) {const n=readVarint(data,cursor);begin=cursor.pos;cursor.pos+=n;}
      else throw Error('Invalid menu wire');
      if (cursor.pos>data.length) throw Error('Truncated menu field');
      fields.push({number,wire,data:data.subarray(begin,cursor.pos),raw:data.subarray(start,cursor.pos)});
    }
    if (cursor.pos!==data.length) throw Error('Menu field limit');
    return fields;
  }
  const MENU_LAYOUT_BYTES = MENU_LAYOUTS.map(utf8);
  function pruneMenuBytes(data, depth=0, budget={count:0}) {
    if (!data.length || data.length>262144 || depth>8 || ++budget.count>1024) return data;
    try {
      const fields=parseMenuBytes(data);
      if (!fields.length) return data;
      const rows=new Map();
      for (const field of fields) {
        if (field.wire!==2 || !menuEvidence(field.data,MENU_LAYOUT_BYTES)) continue;
        const list=rows.get(field.number)||[];
        list.push(field);
        rows.set(field.number,list);
      }
      const remove=new Set();
      for (const siblings of rows.values()) {
        if (siblings.length<2) continue;
        const hits=siblings.filter(field=>menuEvidence(field.data,MENU_ICONS)||menuEvidence(field.data,MENU_LABELS));
        if (hits.length && hits.length<siblings.length) {
          for (const field of hits) {
            const nested=pruneMenuBytes(field.data,depth+1,budget);
            if (nested===field.data) remove.add(field);
          }
        }
      }
      let changed=remove.size>0;
      const output=[];
      for (const field of fields) {
        if (remove.has(field)) continue;
        const value=field.wire===2?pruneMenuBytes(field.data,depth+1,budget):field.data;
        if (value===field.data) output.push(field.raw);
        else {changed=true;output.push(concat([varint(field.number*8+2),varint(value.length),value]));}
      }
      return changed?concat(output):data;
    } catch (_) {return data;}
  }
  function hiddenMenuElement(item) {
    let layout = false, target = false;
    walk(item, node => {
      if (node.type === 'response_browse_LayoutRender' && MENU_LAYOUTS.includes(text(node, 1).split('|')[0])) layout = true;
      for (const field of node.fields) {
        if (field.child || field.wire !== 2) continue;
        if (menuEvidence(field.data, MENU_ICONS)) target = true;
        if (menuEvidence(field.data, MENU_LAYOUTS.map(utf8))) layout = true;
      }
    });
    return layout && target;
  }
  function hiddenGuideEntry(item) {
    const entry = child(item, 318370163) || child(item, 117501096);
    if (entry && ['FEshorts', 'FEmini_app_destination'].includes(text(entry, 1))) return true;
    const icon = entry && child(entry, 5);
    if (icon && GAME_ICONS.has(integer(icon, 1))) return true;
    let blocked = false;
    walk(item, node => {
      for (const field of node.fields) {
        if (!field.child && field.wire === 2 && guideEvidence(field.data)) blocked = true;
      }
    });
    return blocked;
  }
  function hiddenTopbar(item) {
    const direct = child(item, 65153809);
    const nested = child(item, 322055134);
    if (nested) {
      const button = child(nested, 1);
      if (button && hiddenTopbar(button)) return true;
    }
    if (!direct) return false;
    const icon = child(direct, 8);
    if (icon && GAME_ICONS.has(integer(icon, 1))) return true;
    return direct.fields.some(field => !field.child && field.wire === 2 && menuEvidence(field.data, MENU_ICONS));
  }
  function filterGuide(node) {
    walk(node, current => {
      if (current.type === 'response_guide_GuideSectionRenderer') {
        current.fields = current.fields.filter(field => field.number !== 1 || !field.child || !hiddenGuideEntry(field.child));
      }
      if (current.type === 'response_guide_MobileTopbarRenderer') {
        current.fields = current.fields.filter(field => field.number !== 4 || !field.child || !hiddenTopbar(field.child));
      }
    });
  }
  function adContent(item) {
    let blocked = false;
    walk(item, node => {
      if (node.type === 'response_browse_LayoutRender' && text(node, 1).split('|')[0] === 'inline_injection_entrypoint_layout.eml') blocked = true;
      if (node.type !== 'response_browse_VideoContent') return;
      for (const field of node.fields) {
        if (field.wire !== 2 || !Object.prototype.hasOwnProperty.call(AD_PATHS, field.number)) continue;
        for (const path of AD_PATHS[field.number]) {
          try { if (rawStrings(field.data, path)) blocked = true; } catch (_) {}
        }
      }
    });
    return blocked;
  }
  function filterFeed(node) {
    walk(node, current => {
      if (current.type === 'response_browse_Content') {
        current.fields = current.fields.filter(field => field.number !== 153515154 || !field.child || !(hiddenElement(field.child) || adContent(field.child) || hiddenMenuElement(field.child)));
      }
      if (current.type === 'response_browse_SectionListSupportedRenderer') {
        current.fields = current.fields.filter(field => {
          if (field.number !== 51845067 || !field.child) return true;
          const shelf = child(field.child, 5);
          return !shelf || !child(shelf, 51431404);
        });
      }
      if (current.type === 'response_browse_ItemSectionRenderer' || current.type === 'response_browse_ReelShelfRenderer') {
        current.fields = current.fields.filter(field => field.number !== 1 || !field.child || !(adContent(field.child) || hiddenElement(field.child) || hiddenMenuElement(field.child)));
      }
    });
  }
  function processPlayer(player) {
    player.fields = player.fields.filter(field => !(field.wire === 2 && (field.number === 7 || field.number === 68)));
    const tracking=child(player,9);
    if(tracking) drop(tracking,18);
    const status=child(player,2);
    if(status) {
      let background=child(status,11);
      if(!background){background=make('response_player_BackgroundSupportedRenderer');set(status,11,background,'message');}
      let ability=child(background,64657230);
      if(!ability){ability=make('response_player_BackgroundAbility');set(background,64657230,ability,'message');}
      if(integer(ability,1)!==1)set(ability,1,true);
    }
  }
  function processSettings(node) {
    let found=false;
    walk(node, item=>{
      if(item.type==='response_setting_BackgroundPlayBackSettingRenderer'){
        found=true;
        if(integer(item,2)!==1)set(item,2,true);
      }
    });
    if(!found){
      const item=make('response_setting_SettingItem');
      const bg=make('response_setting_BackgroundPlayBackSettingRenderer');
      set(bg,2,true);
      const icon=make('response_setting_Icon');set(icon,1,1093);add(bg,14,icon);
      add(item,88478200,bg);add(node,6,item);
    }
  }
  function transform(node, route) {
    if (route === 'account/get_setting') processSettings(node);
    else if (route === 'guide') filterGuide(node);
    else if (route === 'player') processPlayer(node);
    else if (route === 'reel/reel_watch_sequence') {
      node.fields = node.fields.filter(field => {
        if (field.number !== 2 || !field.child) return true;
        const command = child(field.child, 1);
        const endpoint = command && child(command, 139608561);
        const ad = endpoint && child(endpoint, 16);
        return !ad || integer(ad, 1) !== 1;
      });
    } else if (route === 'get_watch') {
      for (const field of all(node, 1)) {
        if (!field.child) continue;
        const player = child(field.child, 2); if (player) processPlayer(player);
        const next = child(field.child, 3); if (next) filterFeed(next);
      }
    } else if (route === 'browse') {
      filterHomeTabs(node);
      filterFeed(node);
    } else if (route === 'next' || route === 'search') filterFeed(node);
    return node;
  }
  function same(a, b) { return a.length === b.length && a.every((value, index) => value === b[index]); }
  function jsonPlayer(value) {
    if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
    let changed=false;
    for(const key of ['adPlacements','adSlots','playerAds']) {
      if(Object.prototype.hasOwnProperty.call(value,key)){delete value[key];changed=true;}
    }
    if(value.playabilityStatus&&typeof value.playabilityStatus==='object'&&!Array.isArray(value.playabilityStatus)){
      const s=value.playabilityStatus;
      if(!s.backgroundPlayerRender||typeof s.backgroundPlayerRender!=='object')s.backgroundPlayerRender={};
      if(!s.backgroundPlayerRender.backgroundAbility||typeof s.backgroundPlayerRender.backgroundAbility!=='object')s.backgroundPlayerRender.backgroundAbility={};
      if(s.backgroundPlayerRender.backgroundAbility.active!==true){s.backgroundPlayerRender.backgroundAbility.active=true;changed=true;}
    }
    if(value.playbackTracking&&Object.prototype.hasOwnProperty.call(value.playbackTracking,'pageadViewthroughconversion')){delete value.playbackTracking.pageadViewthroughconversion;changed=true;}
    return changed;
  }
  function jsonResponse(body,route) {
    if(body.length>MAX_BODY)return body;
    let start=0;while(start<body.length&&[9,10,13,32].includes(body[start]))start++;
    if(body[start]!==123)return body;
    if(route!=='player'&&route!=='get_watch')return body;
    let encoded='';
    for(let i=0;i<body.length;i++)encoded+='%'+body[i].toString(16).padStart(2,'0');
    const value=JSON.parse(decodeURIComponent(encoded));
    let changed=route==='player'&&jsonPlayer(value);
    if(route==='get_watch'&&value&&Array.isArray(value.contents)) {
      for(const item of value.contents) if(item&&jsonPlayer(item.playerResponse||item.player))changed=true;
    }
    return changed?utf8(JSON.stringify(value)):body;
  }
  function initFallback(url,argument) {
    const enabled=argument===undefined||argument===''||String(argument)==='true';
    if(!enabled||!/^https:\/\/[a-z0-9-]+\.googlevideo\.com\/initplayback\?[^#]+$/i.test(url)||!/[?&]ack(?:=[^&#]*)?(?:&|$)/.test(url))return {};
    return {response:{status:200,headers:{'Content-Type':'text/plain'},body:new Uint8Array(0)}};
  }
  function run() {
    let result = {};
    try {
      if(typeof $response==='undefined') {
        $done(initFallback($request.url,typeof $argument==='undefined'?undefined:$argument));
        return;
      }
      const match = /^https:\/\/(?:youtubei\.googleapis\.com|music\.youtube\.com)\/youtubei\/v1\/(browse|next|player|search|reel\/reel_watch_sequence|get_watch|guide|account\/get_setting)(?:\?[^#]*)?$/.exec($request.url);
      if (match && ($request.method === 'POST' || ($request.method === 'GET' && ['guide','account/get_setting'].includes(match[1]))) && Number($response.status) === 200 && $response.body != null) {
        const original = bytes($response.body);
        if (original.length) {
          let first=0;while(first<original.length&&[9,10,13,32].includes(original[first]))first++;
          const changed = original[first]===123 ? jsonResponse(original,match[1]) : encode(transform(decode(original, ROUTES[match[1]]), match[1]));
          if (!same(original, changed)) result = { body: changed };
        }
      }
    } catch (_) {}
    $done(result);
  }
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = { SCHEMAS, ROUTES, decode, encode, transform, make, set, add, child, all, text, integer, bytes, varint, concat, run, adUrl, hiddenLayout, initFallback };
  }
  if (typeof $done === 'function') run();
})();
