# LB GUI

## Customizing the UI.
Want to add your own logo? Replace `frontend/src/components/logo.png` with your own logo.

If you have your own email address that forwards scans to Laikaboss set the environment variable `SCAN_EMAIL` before building this UI.
In a similar fashion, if you want to host the website at a different route other than `/` set the environment variable `PUBLIC_PATH` to a custom route `/custom`.

The variables that can be set are specified in `frontend/src/component/webpack.config.js` as `process.env` variables in the vue project.



## Dependency install
Install nodejs and npm:
```
apt install nodejs
apt install npm
```

Install frontend dependencies: `npm i`

## Dev 
Run laikarestd (I use Docker to run it) `python laikarestd.py`

Run the hot-reload dev server on another tab `cd frontend` (this directory ) and execute `npm run dev`. Changes to any 
file under this `frontend` directory will auto-reload.

`firefox http://localhost:8000`

## Prod
Build the frontend `npm run build`

Make sure you have `laikarestd` running, otherwise the GUI won't be able to auth, etc...

Serve the static files under `<project-root>/frontend/dist` with apache, nginx, or another server of your choice.
