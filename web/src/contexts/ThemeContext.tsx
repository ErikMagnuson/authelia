import React, { createContext, useCallback, useContext, useEffect, useState } from "react";

import { Theme, ThemeProvider } from "@mui/material";

import { LocalStorageThemeName } from "@constants/LocalStorage";
import { getLocalStorageWithFallback, localStorageAvailable } from "@services/LocalStorage";
import * as themes from "@themes/index";
import { getTheme } from "@utils/Configuration";

export const ThemeContext = createContext<ValueProps | null>(null);

export interface Props {
    children: React.ReactNode;
}

export interface ValueProps {
    theme: Theme;
    themeName: string;
    setThemeName: (value: string) => void;
}

export default function ThemeContextProvider(props: Props) {
    const [theme, setTheme] = useState(GetCurrentTheme());
    const [themeName, setThemeName] = useState(GetCurrentThemeName());
    const isLocalStorageAvailable = localStorageAvailable();

    useEffect(() => {
        if (themeName === themes.ThemeNameAuto) {
            const query = window.matchMedia("(prefers-color-scheme: dark)");
            // MediaQueryLists does not inherit from EventTarget in Internet Explorer
            if (query.addEventListener) {
                query.addEventListener("change", mediaQueryListener);

                return () => {
                    query.removeEventListener("change", mediaQueryListener);
                };
            }
        }

        setTheme(ThemeFromName(themeName));
    }, [themeName]);

    useEffect(() => {
        window.addEventListener("storage", storageListener);

        return () => {
            window.removeEventListener("storage", storageListener);
        };
    }, []);

    const storageListener = (ev: StorageEvent): any => {
        if (ev.key !== LocalStorageThemeName) {
            return;
        }

        if (ev.newValue && ev.newValue !== "") {
            setThemeName(ev.newValue);
        } else {
            setThemeName(getUserThemeName());
        }
    };

    const mediaQueryListener = (ev: MediaQueryListEvent) => {
        setTheme(ev.matches ? themes.Dark : themes.Light);
    };

    const callback = useCallback(
        (name: string) => {
            setThemeName(name);

            if (isLocalStorageAvailable) {
                window.localStorage.setItem(LocalStorageThemeName, name);
            }
        },
        [isLocalStorageAvailable],
    );

    return (
        <ThemeContext.Provider
            value={{
                theme,
                themeName,
                setThemeName: callback,
            }}
        >
            <ThemeWrapper>{props.children}</ThemeWrapper>
        </ThemeContext.Provider>
    );
}

export function useThemeContext() {
    const context = useContext(ThemeContext);
    if (!context) {
        throw new Error("useThemeContext must be used within a ThemeContextProvider");
    }

    return context;
}

function ThemeWrapper(props: Props) {
    const { theme } = useThemeContext();

    return <ThemeProvider theme={theme}>{props.children}</ThemeProvider>;
}

function GetCurrentThemeName() {
    if (localStorageAvailable()) {
        const local = window.localStorage.getItem(LocalStorageThemeName);

        if (local) {
            return local;
        }
    }

    return getTheme();
}

function GetCurrentTheme() {
    return ThemeFromName(GetCurrentThemeName());
}

function ThemeFromName(name: string) {
    switch (name) {
        case themes.ThemeNameLight:
            return themes.Light;
        case themes.ThemeNameDark:
            return themes.Dark;
        case themes.ThemeNameGrey:
            return themes.Grey;
        case themes.ThemeNameAuto:
            return window.matchMedia("(prefers-color-scheme: dark)").matches ? themes.Dark : themes.Light;
        default:
            return window.matchMedia("(prefers-color-scheme: dark)").matches ? themes.Dark : themes.Light;
    }
}

const getUserThemeName = () => {
    return getLocalStorageWithFallback(LocalStorageThemeName, getTheme());
};
