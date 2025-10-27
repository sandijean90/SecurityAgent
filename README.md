# VulnerabilityAgent
An AI Security Agent that authenticates into Github, assesses for known dependency exploits, and writes Github issues to address them

To use this agent:
1. Install the beeai platform https://docs.beeai.dev/introduction/quickstart
2. Start the platform with observability enabled (using Phoneix by Arize)
```
beeai platform start --set phoenix.enabled=true
```
3. Navigate to [http://localhost:6006](http://localhost:6006) to see your trace
4. Launch the UI and follow the directions set your provider, API key, and chose your model. Note that this repo was only tested with gpt-5-mini, so using other models will produce unverifiable results.

```
beeai ui
```

5. 



