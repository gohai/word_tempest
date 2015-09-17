import processing.net.*;
import java.util.Set;

// Client for word_tempest.py
// by Gottfried Haider 2015

Server s;
Client c;
int timeout = 0;
String words[];
int last;

void setup() 
{
  s = new Server(this, 8080);
  size(1440, 900);
  background(0);
}

void draw() 
{
  // clear the screen if nothing received in the last 10 sec
  if (10000 < millis()-last) {
    background(0);
  }

  // quick & dirty HTTP server
  c = s.available();
  if (c != null) {
    // read header
    String input;
    do {
      input = c.readStringUntil('\n');
    } while (input != null && input.length() != 2);

    // read payload
    String payload = "";
    do {
      input = c.readString();
      if (input != null) {
        payload = payload + input;
      }
    } while (input != null);

    c.stop();
    
    // parse JSON
    try {
      JSONObject json = JSONObject.parse(payload);
      Set<String> keys = json.keys();
      words = new String[keys.size()];
      int i = 0;
      int max = 0;
      for (String key : keys) {
       words[i] = key;
       i++;
       if (max < json.getInt(key)) {
         max = json.getInt(key);
       }
      }
      // empty set, not really sure why
      if (keys.size() < 2) {
        return;
      }
      background(0);
      last = millis();
      int x = 0;
      int y = 0;
      words = sort(words);
      for (String key : words) {
        fill(50+205*(float(json.getInt(key))/max));
        text(key, x, y);
        y += 30;
        if (y > height) {
          y = 0;
          x += 100;
        }
      }
    } catch (Exception e)  {
      // JSON decoding failed, ignore
    }
  }
}
