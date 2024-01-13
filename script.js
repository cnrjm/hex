var colours = [
  "#000000",
  "#040720",
  "#0C090A",
  "#34282C",
  "#3B3131",
  "#3A3B3C",
  "#454545",
  "#413839",
  "#3D3C3A",
  "#463E3F",
  "#4C4646",
  "#504A4B",
  "#565051",
  "#52595D",
  "#5C5858",
  "#625D5D",
  "#666362",
  "#696969",
  "#686A6C",
  "#6D6968",
  "#726E6D",
  "#736F6E",
  "#757575",
  "#797979",
  "#837E7C",
  "#808080",
  "#848482",
  "#8C8C8C",
  "#8D918D",
  "#A9A9A9",
  "#B6B6B4",
  "#C0C0C0",
  "#C9C0BB",
  "#D1D0CE",
  "#CECECE",
  "#D3D3D3",
  "#DADBDD",
  "#DCDCDC",
  "#E5E4E2",
  "#BCC6CC",
  "#98AFC7",
  "#838996",
  "#778899",
  "#708090",
  "#6D7B8D",
  "#657383",
  "#616D7E",
  "#646D7E",
  "#566D7E",
  "#737CA1",
  "#728FCE",
  "#4863A0",
  "#2F539B",
  "#2B547E",
  "#36454F",
  "#29465B",
  "#2B3856",
  "#123456",
  "#151B54",
  "#191970",
  "#000080",
  "#151B8D",
  "#00008B",
  "#15317E",
  "#0000A0",
  "#0000A5",
  "#0020C2",
  "#0000CD",
  "#0041C2",
  "#2916F5",
  "#0000FF",
  "#0002FF",
  "#0909FF",
  "#1F45FC",
  "#2554C7",
  "#1569C7",
  "#1974D2",
  "#2B60DE",
  "#4169E1",
  "#2B65EC",
  "#306EFF",
  "#157DEC",
  "#1589FF",
  "#1E90FF",
  "#368BC1",
  "#4682B4",
  "#488AC7",
  "#357EC7",
  "#3090C7",
  "#659EC7",
  "#87AFC7",
  "#95B9C7",
  "#6495ED",
  "#6698FF",
  "#56A5EC",
  "#38ACEC",
  "#00BFFF",
  "#3BB9FF",
  "#5CB3FF",
  "#79BAEC",
  "#82CAFF",
  "#87CEFA",
  "#87CEEB",
  "#A0CFEC",
  "#B7CEEC",
  "#B4CFEC",
  "#ADDFFF",
  "#C2DFFF",
  "#C6DEFF",
  "#BDEDFF",
  "#B0E0E6",
  "#AFDCEC",
  "#ADD8E6",
  "#B0CFDE",
  "#C9DFEC",
  "#D5D6EA",
  "#E3E4FA",
  "#DBE9FA",
  "#E6E6FA",
  "#EBF4FA",
  "#F0F8FF",
  "#F8F8FF",
  "#F0FFFF",
  "#E0FFFF",
  "#CCFFFF",
  "#9AFEFF",
  "#7DFDFE",
  "#57FEFF",
  "#00FFFF",
  "#0AFFFF",
  "#50EBEC",
  "#4EE2EC",
  "#16E2F5",
  "#8EEBEC",
  "#AFEEEE",
  "#CFECEC",
  "#B3D9D9",
  "#81D8D0",
  "#77BFC7",
  "#92C7C7",
  "#78C7C7",
  "#7BCCB5",
  "#66CDAA",
  "#93E9BE",
  "#AAF0D1",
  "#93FFE8",
  "#7FFFD4",
  "#01F9C6",
  "#40E0D0",
  "#48D1CC",
  "#48CCCD",
  "#46C7C7",
  "#43C6DB",
  "#00CED1",
  "#43BFC7",
  "#20B2AA",
  "#3EA99F",
  "#5F9EA0",
  "#3B9C9C",
  "#008B8B",
  "#00827F",
  "#008080",
  "#007C80",
  "#045F5F",
  "#045D5D",
  "#033E3E",
  "#25383C",
  "#2C3539",
  "#3C565B",
  "#4C787E",
  "#5E7D7E",
  "#307D7E",
  "#348781",
  "#438D80",
  "#4E8975",
  "#1F6357",
  "#306754",
  "#006A4E",
  "#2E8B57",
  "#1B8A6B",
  "#31906E",
  "#00A36C",
  "#34A56F",
  "#1AA260",
  "#3EB489",
  "#50C878",
  "#22CE83",
  "#3CB371",
  "#7C9D8E",
  "#78866B",
  "#848B79",
  "#617C58",
  "#728C00",
  "#6B8E23",
  "#808000",
  "#555D50",
  "#556B2F",
  "#4E5B31",
  "#3A5F0B",
  "#4B5320",
  "#667C26",
  "#4E9258",
  "#08A04B",
  "#387C44",
  "#347235",
  "#27742C",
  "#347C2C",
  "#227442",
  "#228B22",
  "#008000",
  "#006400",
  "#056608",
  "#046307",
  "#355E3B",
  "#254117",
  "#004225",
  "#437C17",
  "#347C17",
  "#6AA121",
  "#8A9A5B",
  "#3F9B0B",
  "#4AA02C",
  "#41A317",
  "#12AD2B",
  "#3EA055",
  "#73A16C",
  "#6CBB3C",
  "#6CC417",
  "#4CC417",
  "#32CD32",
  "#52D017",
  "#4CC552",
  "#54C571",
  "#89C35C",
  "#85BB65",
  "#99C68E",
  "#A0D6B4",
  "#8FBC8F",
  "#829F82",
  "#A2AD9C",
  "#B8BC86",
  "#9CB071",
  "#8FB31D",
  "#B0BF1A",
  "#B2C248",
  "#9DC209",
  "#A1C935",
  "#9ACD32",
  "#77DD77",
  "#7FE817",
  "#59E817",
  "#57E964",
  "#16F529",
  "#5EFB6E",
  "#36F57F",
  "#00FF7F",
  "#00FA9A",
  "#12E193",
  "#5FFB17",
  "#00FF00",
  "#7CFC00",
  "#66FF00",
  "#7FFF00",
  "#87F717",
  "#98F516",
  "#B1FB17",
  "#ADF802",
  "#ADFF2F",
  "#BDF516",
  "#DAEE01",
  "#E2F516",
  "#CCFB5D",
  "#BCE954",
  "#64E986",
  "#90EE90",
  "#6AFB92",
  "#98FB98",
  "#98FF98",
  "#B5EAAA",
  "#E3F9A6",
  "#C3FDB8",
  "#C2E5D3",
  "#DBF9DB",
  "#E8F1D4",
  "#F0FFF0",
  "#F5FFFA",
  "#FFFACD",
  "#FFFFC2",
  "#FFFFCC",
  "#FFFDD0",
  "#FAFAD2",
  "#FFFFE0",
  "#F5F5DC",
  "#FFF8DC",
  "#FBF6D9",
  "#FAEBD7",
  "#FFF0DB",
  "#FFEFD5",
  "#F7E7CE",
  "#FFEBCD",
  "#FFE4C4",
  "#F5DEB3",
  "#FFE4B5",
  "#FFE5B4",
  "#FED8B1",
  "#FFDAB9",
  "#FBD5AB",
  "#FFDEAD",
  "#FBE7A1",
  "#F3E3C3",
  "#F0E2B6",
  "#F1E5AC",
  "#F3E5AB",
  "#ECE5B6",
  "#E8E4C9",
  "#EEE8AA",
  "#F0E68C",
  "#EDDA74",
  "#EDE275",
  "#FFE87C",
  "#FFF380",
  "#FAF884",
  "#FFFF33",
  "#FFFF00",
  "#FFEF00",
  "#F5E216",
  "#FFDB58",
  "#FFDF00",
  "#F9DB24",
  "#EED202",
  "#FFD801",
  "#FFD700",
  "#FDD017",
  "#FFCE44",
  "#EAC117",
  "#F6BE00",
  "#F2BB66",
  "#FBB917",
  "#FDBD01",
  "#FBB117",
  "#FFAE42",
  "#FFA62F",
  "#FFA600",
  "#FFA500",
  "#EE9A4D",
  "#F4A460",
  "#E2A76F",
  "#C19A6B",
  "#E6BF83",
  "#DEB887",
  "#D2B48C",
  "#C8AD7F",
  "#C2B280",
  "#BCB88A",
  "#C8B560",
  "#C9BE62",
  "#C9AE5D",
  "#BDB76B",
  "#BAB86C",
  "#B5A642",
  "#C7A317",
  "#D4AF37",
  "#E9AB17",
  "#E8A317",
  "#DAA520",
  "#D4A017",
  "#C68E17",
  "#B8860B",
  "#C58917",
  "#CD853F",
  "#CD7F32",
  "#C88141",
  "#B87333",
  "#AA6C39",
  "#A97142",
  "#AB784E",
  "#966F33",
  "#806517",
  "#665D1E",
  "#8E7618",
  "#8B8000",
  "#827839",
  "#8A865D",
  "#93917C",
  "#9F8C76",
  "#AF9B60",
  "#827B60",
  "#786D5F",
  "#483C32",
  "#4A412A",
  "#493D26",
  "#513B1C",
  "#3D3635",
  "#3B2F2F",
  "#49413F",
  "#43302E",
  "#622F22",
  "#5C3317",
  "#644117",
  "#654321",
  "#704214",
  "#804A00",
  "#6F4E37",
  "#835C3B",
  "#7F5217",
  "#7F462C",
  "#A0522D",
  "#8B4513",
  "#8A4117",
  "#7E3817",
  "#7E3517",
  "#954535",
  "#9E4638",
  "#C34A2C",
  "#B83C08",
  "#C04000",
  "#EB5406",
  "#C35817",
  "#B86500",
  "#B5651D",
  "#B76734",
  "#C36241",
  "#CB6D51",
  "#C47451",
  "#D2691E",
  "#CC6600",
  "#E56717",
  "#E66C2C",
  "#FF6700",
  "#FF5F1F",
  "#FE632A",
  "#F87217",
  "#FF7900",
  "#F88017",
  "#FF8C00",
  "#F87431",
  "#FF7722",
  "#E67451",
  "#FF8040",
  "#FF7F50",
  "#F88158",
  "#F9966B",
  "#FFA07A",
  "#F89880",
  "#E9967A",
  "#E78A61",
  "#DA8A67",
  "#FF8674",
  "#FA8072",
  "#F98B88",
  "#F08080",
  "#F67280",
  "#E77471",
  "#F75D59",
  "#E55451",
  "#CD5C5C",
  "#FF6347",
  "#E55B3C",
  "#FF4500",
  "#FF0000",
  "#FD1C03",
  "#FF2400",
  "#F62217",
  "#F70D1A",
  "#F62817",
  "#E42217",
  "#E41B17",
  "#DC381F",
  "#C24641",
  "#C11B17",
  "#B22222",
  "#B21807",
  "#A52A2A",
  "#A70D2A",
  "#9F000F",
  "#931314",
  "#990000",
  "#990012",
  "#8B0000",
  "#8F0B0B",
  "#800000",
  "#8C001A",
  "#7E191B",
  "#800517",
  "#733635",
  "#660000",
  "#551606",
  "#560319",
  "#3F000F",
  "#3D0C02",
  "#2F0909",
  "#2B1B17",
  "#550A35",
  "#810541",
  "#7D0541",
  "#7D0552",
  "#872657",
  "#7E354D",
  "#7F4E52",
  "#7F525D",
  "#7F5A58",
  "#997070",
  "#B1907F",
  "#B38481",
  "#BC8F8F",
  "#C5908E",
  "#C48793",
  "#CC7A8B",
  "#C48189",
  "#C08081",
  "#D58A94",
  "#E799A3",
  "#E8ADAA",
  "#C9A9A6",
  "#C4AEAD",
  "#E6C7C2",
  "#ECC5C0",
  "#FFCBA4",
  "#F8B88B",
  "#EDC9AF",
  "#FFDDCA",
  "#FDD7E4",
  "#F2D4D7",
  "#FFE6E8",
  "#FFE4E1",
  "#FFDFDD",
  "#FBCFCD",
  "#FFCCCB",
  "#F6C6BD",
  "#FBBBB9",
  "#FFC0CB",
  "#FFB6C1",
  "#FFB8BF",
  "#FFB2D0",
  "#FAAFBE",
  "#FAAFBA",
  "#F9A7B0",
  "#FEA3AA",
  "#E7A1B0",
  "#E38AAE",
  "#F778A1",
  "#E5788F",
  "#E56E94",
  "#DB7093",
  "#D16587",
  "#C25A7C",
  "#C25283",
  "#E75480",
  "#F660AB",
  "#FF69B4",
  "#FC6C85",
  "#F6358A",
  "#F52887",
  "#FF007F",
  "#FF1493",
  "#F535AA",
  "#FF33AA",
  "#FD349C",
  "#E45E9D",
  "#E759AC",
  "#E3319D",
  "#DA1884",
  "#E4287C",
  "#FA2A55",
  "#E30B5D",
  "#DC143C",
  "#C32148",
  "#C21E56",
  "#C12869",
  "#C12267",
  "#CA226B",
  "#CC338B",
  "#C71585",
  "#C12283",
  "#B3446C",
  "#B93B8F",
  "#DA70D6",
  "#DF73D4",
  "#EE82EE",
  "#FF77FF",
  "#F433FF",
  "#FF00FF",
  "#E238EC",
  "#D462FF",
  "#C45AEC",
  "#BA55D3",
  "#A74AC7",
  "#B048B5",
  "#B666D2",
  "#D291BC",
  "#A17188",
  "#915F6D",
  "#7E587E",
  "#614051",
  "#583759",
  "#5E5A80",
  "#4E5180",
  "#6A5ACD",
  "#6960EC",
  "#5865F2",
  "#736AFF",
  "#7B68EE",
  "#7575CF",
  "#6667AB",
  "#6F2DA8",
  "#6A0DAD",
  "#6C2DC7",
  "#5539CC",
  "#5453A6",
  "#483D8B",
  "#4E387E",
  "#571B7E",
  "#4B0150",
  "#36013F",
  "#2E1A47",
  "#461B7E",
  "#4B0082",
  "#342D7E",
  "#663399",
  "#6A287E",
  "#8B008B",
  "#800080",
  "#86608E",
  "#9932CC",
  "#9400D3",
  "#8D38C9",
  "#A23BEC",
  "#B041FF",
  "#842DCE",
  "#8A2BE2",
  "#7A5DC7",
  "#7F38EC",
  "#9D00FF",
  "#8E35EF",
  "#893BFF",
  "#9370DB",
  "#8467D7",
  "#9172EC",
  "#9E7BFF",
  "#967BB6",
  "#B09FCA",
  "#CCCCFF",
  "#DCD0FF",
  "#C8A2C8",
  "#E0B0FF",
  "#D891EF",
  "#C38EC7",
  "#DDA0DD",
  "#E6A9EC",
  "#F2A2E8",
  "#F9B7FF",
  "#C6AEC7",
  "#D2B9D3",
  "#D8BFD8",
  "#DFD3E3",
  "#E9CFEC",
  "#FCDFFF",
  "#EBDDE2",
  "#E1D9D1",
  "#E9E4D4",
  "#EFEBD8",
  "#EDE6D6",
  "#F8F0E3",
  "#FAF0DD",
  "#FFF8E7",
  "#F8F6F0",
  "#F3E8EA",
  "#FFF0F5",
  "#FDEEF4",
  "#FFF9E3",
  "#FEF0E3",
  "#EAEEE9",
  "#FAF0E6",
  "#FFF5EE",
  "#F9F6EE",
  "#FAF5EF",
  "#FFFAF0",
  "#FFFFF0",
  "#FFFFF4",
  "#FFFFF7",
  "#F5F5F5",
  "#FBFBF9",
  "#FFFAFA",
  "#FEFCFF",
  "#FFFEFA",
  "#FFFFFF"
]

function getRandomColour() {
  var colourNames = Object.keys(colours);
  var randomColourName = colourNames[Math.floor(Math.random() * colourNames.length)];
  var randomColourCode = colours[randomColourName];

  // Update the HTML elements with the random color and its code
  document.getElementById('colourName').textContent = randomColourName.toUpperCase();
  document.getElementById('colourCode').textContent = randomColourCode;
  document.getElementById('colourBox').style.backgroundColor = randomColourCode;

  return randomColourCode.substring(1).toLowerCase(); // Extract and return the correct answer in lowercase
}

window.onload = function () {
  const targetWord = getRandomColour();
  console.log("Correct Answer:", targetWord);

  // Rest of your code...
  const WORD_LENGTH = 6;
  const FLIP_ANIMATION_DURATION = 500;
  const DANCE_ANIMATION_DURATION = 500;
  const keyboard = document.querySelector("[data-keyboard]");
  const alertContainer = document.querySelector("[data-alert-container]");
  const guessGrid = document.querySelector("[data-guess-grid]");

console.log("Correct Answer:", targetWord);

startInteraction()

function startInteraction() {
  document.addEventListener("click", handleMouseClick)
  document.addEventListener("keydown", handleKeyPress)
}

function stopInteraction() {
  document.removeEventListener("click", handleMouseClick)
  document.removeEventListener("keydown", handleKeyPress)
}

function handleMouseClick(e) {
  if (e.target.matches("[data-key]")) {
    pressKey(e.target.dataset.key)
    return
  }

  if (e.target.matches("[data-enter]")) {
    submitGuess()
    return
  }

  if (e.target.matches("[data-delete]")) {
    deleteKey()
    return
  }
}

function handleKeyPress(e) {
  if (e.key === "Enter") {
    submitGuess()
    return
  }

  if (e.key === "Backspace" || e.key === "Delete") {
    deleteKey()
    return
  }

  if (e.key.match(/^[a-z 0-9]$/)) {
    pressKey(e.key)
    return
  }
}

function pressKey(key) {
  const activeTiles = getActiveTiles()
  if (activeTiles.length >= WORD_LENGTH) return
  const nextTile = guessGrid.querySelector(":not([data-letter])")
  nextTile.dataset.letter = key.toLowerCase()
  nextTile.textContent = key
  nextTile.dataset.state = "active"
}

function deleteKey() {
  const activeTiles = getActiveTiles()
  const lastTile = activeTiles[activeTiles.length - 1]
  if (lastTile == null) return
  lastTile.textContent = ""
  delete lastTile.dataset.state
  delete lastTile.dataset.letter
}

function submitGuess() {
  const activeTiles = [...getActiveTiles()];
  if (activeTiles.length !== WORD_LENGTH) {
    showAlert("Not enough letters");
    shakeTiles(activeTiles);
    return;
  }

  const guess = activeTiles.reduce((word, tile) => {
    return word + tile.dataset.letter;
  }, "").toLowerCase(); // Convert the guess to lowercase

  const targetHexCode = document.getElementById('colourCode').textContent.toLowerCase();

  // Remove "#" from the target hex code for comparison
  const cleanedTargetHexCode = targetHexCode.replace("#", "");

  if (guess === cleanedTargetHexCode) {
    stopInteraction();
    activeTiles.forEach((...params) => flipTile(...params, guess));
  } else {
    provideGuessFeedback(guess, cleanedTargetHexCode);
    shakeTiles(activeTiles);
  }
}

function provideGuessFeedback(guess, target) {
  const tiles = getActiveTiles();
  const incorrectLetters = [];

  tiles.forEach((tile, index) => {
    const letter = tile.dataset.letter;

    if (target.includes(letter)) {
      if (target[index] === letter) {
        tile.dataset.state = "correct";
      } else {
        tile.dataset.state = "wrong-location";
      }
    } else {
      tile.dataset.state = "wrong";
      incorrectLetters.push(letter);
    }
  });

  // Add a class to incorrect keys on the keyboard
  const keyboardKeys = keyboard.querySelectorAll("[data-key]");
  keyboardKeys.forEach((key) => {
    const keyLetter = key.dataset.key.toLowerCase();
    if (incorrectLetters.includes(keyLetter)) {
      key.classList.add("incorrect-key");
    }
  });
}

function flipTile(tile, index, array, guess) {
  const letter = tile.dataset.letter;
  const key = keyboard.querySelector(`[data-key="${letter}"i]`);

  tile.classList.add("flip");
  key.classList.add("flip");

  setTimeout(() => {
    // Check if the letter is in the correct place
    if (targetWord[index] === letter) {
      tile.dataset.state = "correct";
      key.classList.add("correct");
    } else if (targetWord.includes(letter)) {
      // Check if the letter is correct but in the wrong place
      tile.dataset.state = "wrong-location";
      key.classList.add("wrong-location");
    } else {
      // The letter is incorrect
      tile.dataset.state = "wrong";
      key.classList.add("wrong");
    }

    setTimeout(() => {
      tile.classList.remove("flip");
      key.classList.remove("flip");

      if (index === array.length - 1) {
        startInteraction();
        checkWinLose(guess, array);
      }
    }, 500);
  }, 500);
}

function getActiveTiles() {
  return guessGrid.querySelectorAll('[data-state="active"]')
}

function showAlert(message, duration = 1000) {
  const alert = document.createElement("div")
  alert.textContent = message
  alert.classList.add("alert")
  alertContainer.prepend(alert)
  if (duration == null) return

  setTimeout(() => {
    alert.classList.add("hide")
    alert.addEventListener("transitionend", () => {
      alert.remove()
    })
  }, duration)
}

function shakeTiles(tiles) {
  tiles.forEach(tile => {
    tile.classList.add("shake")
    tile.addEventListener(
      "animationend",
      () => {
        tile.classList.remove("shake")
      },
      { once: true }
    )
  })
}

function checkWinLose(guess, tiles) {
  if (guess === targetWord) {
    showAlert("You Win", 5000)
    danceTiles(tiles)
    stopInteraction()
    return
  }

  const remainingTiles = guessGrid.querySelectorAll(":not([data-letter])")
  if (remainingTiles.length === 0) {
    showAlert(targetWord.toUpperCase(), null)
    stopInteraction()
  }
}

function danceTiles(tiles) {
  tiles.forEach((tile, index) => {
    setTimeout(() => {
      tile.classList.add("dance")
      tile.addEventListener(
        "animationend",
        () => {
          tile.classList.remove("dance")
        },
        { once: true }
      )
    }, (index * DANCE_ANIMATION_DURATION) / 5)
  })
}
};